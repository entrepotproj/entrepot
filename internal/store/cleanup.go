package store

import (
	"context"
	"encoding/json"
	"time"
)

// CleanupPolicy is a stored cleanup policy. Criteria is the JSON form of
// the API's CleanupCriteria (interpreted by internal/cleanup).
type CleanupPolicy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Format      string          `json:"format"`
	Criteria    json.RawMessage `json:"criteria"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

const cleanupPolicySelect = `SELECT id, name, description, format, criteria, created_at, updated_at FROM cleanup_policies`

func scanCleanupPolicy(row interface{ Scan(...any) error }) (*CleanupPolicy, error) {
	var p CleanupPolicy
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Format, &p.Criteria, &p.CreatedAt, &p.UpdatedAt)
	return &p, err
}

func (s *Store) ListCleanupPolicies(ctx context.Context) ([]*CleanupPolicy, error) {
	rows, err := s.pool.Query(ctx, cleanupPolicySelect+` ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list cleanup policies")
	}
	defer rows.Close()
	out := []*CleanupPolicy{}
	for rows.Next() {
		p, err := scanCleanupPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetCleanupPolicy(ctx context.Context, name string) (*CleanupPolicy, error) {
	p, err := scanCleanupPolicy(s.pool.QueryRow(ctx, cleanupPolicySelect+` WHERE name=$1`, name))
	return p, mapErr(err, "cleanup policy "+name)
}

func (s *Store) CreateCleanupPolicy(ctx context.Context, p *CleanupPolicy) (*CleanupPolicy, error) {
	if p.Criteria == nil {
		p.Criteria = json.RawMessage(`{}`)
	}
	out, err := scanCleanupPolicy(s.pool.QueryRow(ctx, `INSERT INTO cleanup_policies (name, description, format, criteria)
		VALUES ($1,$2,$3,$4) RETURNING id, name, description, format, criteria, created_at, updated_at`,
		p.Name, p.Description, p.Format, p.Criteria))
	return out, mapErr(err, "create cleanup policy "+p.Name)
}

func (s *Store) UpdateCleanupPolicy(ctx context.Context, p *CleanupPolicy) (*CleanupPolicy, error) {
	if p.Criteria == nil {
		p.Criteria = json.RawMessage(`{}`)
	}
	out, err := scanCleanupPolicy(s.pool.QueryRow(ctx, `UPDATE cleanup_policies SET description=$2, format=$3, criteria=$4,
		updated_at=now() WHERE name=$1 RETURNING id, name, description, format, criteria, created_at, updated_at`,
		p.Name, p.Description, p.Format, p.Criteria))
	return out, mapErr(err, "cleanup policy "+p.Name)
}

// DeleteCleanupPolicy deletes a policy unless a repository still lists it
// in cleanup.policies (ErrInUse).
func (s *Store) DeleteCleanupPolicy(ctx context.Context, name string) error {
	users, err := s.RepositoriesUsingCleanupPolicy(ctx, name)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errInUse("cleanup policy "+name, users)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM cleanup_policies c WHERE c.name=$1 AND NOT EXISTS
		(SELECT 1 FROM repositories r WHERE r.config->'cleanup'->'policies' ? c.name)`, name)
	if err != nil {
		return mapErr(err, "delete cleanup policy "+name)
	}
	if tag.RowsAffected() == 0 {
		if ok, _ := s.NamedExists(ctx, "cleanup_policies", name); ok {
			return errInUse("cleanup policy "+name, nil)
		}
		return mapErr(errNoRows, "cleanup policy "+name)
	}
	return nil
}

// RepositoriesUsingCleanupPolicy lists repositories whose cleanup.policies
// contains name.
func (s *Store) RepositoriesUsingCleanupPolicy(ctx context.Context, name string) ([]string, error) {
	return s.repoNames(ctx, `SELECT name FROM repositories WHERE config->'cleanup'->'policies' ? $1 ORDER BY name`, name)
}

func (s *Store) repoNames(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapErr(err, "list repositories")
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CleanupComponent is a component with aggregate asset statistics, as
// evaluated by cleanup policies.
type CleanupComponent struct {
	*Component
	// LastDownloadedAt is the most recent download of any of its assets.
	LastDownloadedAt *time.Time
	Assets           int64
	Size             int64
}

// ListCleanupComponents returns every component of a repository with its
// asset statistics.
func (s *Store) ListCleanupComponents(ctx context.Context, repoID string) ([]*CleanupComponent, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.id, c.repository_id, r.name, r.format, c.name, c.version, c.attrs,
		c.created_at, c.updated_at, c.scan_state, c.quarantined, c.scanned_at,
		st.last_dl, st.n, st.size
		FROM components c JOIN repositories r ON r.id = c.repository_id
		LEFT JOIN LATERAL (SELECT max(a.last_downloaded_at) AS last_dl, count(*) AS n, coalesce(sum(a.size), 0)::bigint AS size
			FROM assets a WHERE a.component_id = c.id) st ON true
		WHERE c.repository_id=$1 ORDER BY c.name, c.created_at`, repoID)
	if err != nil {
		return nil, mapErr(err, "list components")
	}
	defer rows.Close()
	out := []*CleanupComponent{}
	for rows.Next() {
		var c Component
		cc := &CleanupComponent{Component: &c}
		if err := rows.Scan(&c.ID, &c.RepositoryID, &c.Repository, &c.Format, &c.Name, &c.Version, &c.Attrs,
			&c.CreatedAt, &c.UpdatedAt, &c.ScanState, &c.Quarantined, &c.ScannedAt,
			&cc.LastDownloadedAt, &cc.Assets, &cc.Size); err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

// TryAdvisoryLock takes a cluster-wide advisory lock for key without
// waiting. ok is false when another session holds it.
func (s *Store) TryAdvisoryLock(ctx context.Context, key string) (release func(), ok bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
		conn.Release()
	}, true, nil
}

// LastAuditEventAt returns the time of the most recent audit event with
// the given action (nil when there is none).
func (s *Store) LastAuditEventAt(ctx context.Context, action string) (*time.Time, error) {
	var t *time.Time
	err := s.pool.QueryRow(ctx, `SELECT max(at) FROM audit_events WHERE action=$1`, action).Scan(&t)
	return t, mapErr(err, "last audit event")
}
