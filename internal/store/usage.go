package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// UsageCounts are summed usage counters.
type UsageCounts struct {
	Requests    int64 `json:"requests"`
	Errors      int64 `json:"errors"`
	Downloads   int64 `json:"downloads"`
	Uploads     int64 `json:"uploads"`
	BytesOut    int64 `json:"bytesOut"`
	BytesIn     int64 `json:"bytesIn"`
	CacheHits   int64 `json:"cacheHits"`
	CacheMisses int64 `json:"cacheMisses"`
}

// UsagePoint is one time bucket of a series.
type UsagePoint struct {
	T time.Time `json:"t"`
	UsageCounts
}

// RepositoryUsage is usage aggregated for one repository.
type RepositoryUsage struct {
	Repository string `json:"repository"`
	Format     string `json:"format"`
	Kind       string `json:"kind"`
	UsageCounts
}

const usageSums = `coalesce(sum(requests),0), coalesce(sum(errors),0), coalesce(sum(downloads),0),
	coalesce(sum(uploads),0), coalesce(sum(bytes_out),0), coalesce(sum(bytes_in),0),
	coalesce(sum(cache_hits),0), coalesce(sum(cache_misses),0)`

func usageTable(hourly bool) string {
	if hourly {
		return "usage_hour"
	}
	return "usage_minute"
}

func scanCounts(row interface{ Scan(...any) error }, c *UsageCounts, extra ...any) error {
	dst := append(extra, &c.Requests, &c.Errors, &c.Downloads, &c.Uploads, &c.BytesOut, &c.BytesIn, &c.CacheHits, &c.CacheMisses)
	return row.Scan(dst...)
}

// repoFilter is NULL (all repositories) or the given IDs.
func repoFilter(ids []string) any {
	if ids == nil {
		return nil
	}
	return ids
}

// UsageTotals sums usage since from for the given repositories (nil = all).
func (s *Store) UsageTotals(ctx context.Context, repoIDs []string, from time.Time, hourly bool) (UsageCounts, error) {
	var c UsageCounts
	err := scanCounts(s.pool.QueryRow(ctx, `SELECT `+usageSums+` FROM `+usageTable(hourly)+`
		WHERE bucket >= $1 AND ($2::uuid[] IS NULL OR repository_id = ANY($2))`, from, repoFilter(repoIDs)), &c)
	return c, mapErr(err, "usage totals")
}

// UsageSeries returns usage binned by stride since from (empty bins are
// omitted; callers fill gaps).
func (s *Store) UsageSeries(ctx context.Context, repoIDs []string, from time.Time, stride time.Duration, hourly bool) ([]UsagePoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT date_bin(make_interval(secs => $3), bucket, $1) AS t, `+usageSums+`
		FROM `+usageTable(hourly)+` WHERE bucket >= $1 AND ($2::uuid[] IS NULL OR repository_id = ANY($2))
		GROUP BY 1 ORDER BY 1`, from, repoFilter(repoIDs), stride.Seconds())
	if err != nil {
		return nil, mapErr(err, "usage series")
	}
	defer rows.Close()
	var out []UsagePoint
	for rows.Next() {
		var p UsagePoint
		if err := scanCounts(rows, &p.UsageCounts, &p.T); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UsageByRepository returns per-repository totals ordered by requests.
func (s *Store) UsageByRepository(ctx context.Context, repoIDs []string, from time.Time, hourly bool, limit int) ([]RepositoryUsage, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `SELECT r.name, r.format, r.kind, `+usageSums+`
		FROM `+usageTable(hourly)+` u JOIN repositories r ON r.id = u.repository_id
		WHERE u.bucket >= $1 AND ($2::uuid[] IS NULL OR u.repository_id = ANY($2))
		GROUP BY r.name, r.format, r.kind ORDER BY 4 DESC, 6 DESC LIMIT $3`, from, repoFilter(repoIDs), limit)
	if err != nil {
		return nil, mapErr(err, "usage by repository")
	}
	defer rows.Close()
	var out []RepositoryUsage
	for rows.Next() {
		var u RepositoryUsage
		if err := scanCounts(rows, &u.UsageCounts, &u.Repository, &u.Format, &u.Kind); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// FormatInventory counts repositories and content for one format.
type FormatInventory struct {
	Format       string `json:"format"`
	Repositories int64  `json:"repositories"`
	Components   int64  `json:"components"`
	Assets       int64  `json:"assets"`
	TotalBytes   int64  `json:"totalBytes"`
}

// Inventory returns content counts per format for the given repositories.
func (s *Store) Inventory(ctx context.Context, repoIDs []string) ([]FormatInventory, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.format, count(DISTINCT r.id),
		coalesce((SELECT count(*) FROM components c JOIN repositories r2 ON r2.id=c.repository_id
		          WHERE r2.format=r.format AND ($1::uuid[] IS NULL OR r2.id = ANY($1))),0),
		coalesce((SELECT count(*) FROM assets a JOIN repositories r2 ON r2.id=a.repository_id
		          WHERE r2.format=r.format AND ($1::uuid[] IS NULL OR r2.id = ANY($1))),0),
		coalesce((SELECT sum(size) FROM assets a JOIN repositories r2 ON r2.id=a.repository_id
		          WHERE r2.format=r.format AND ($1::uuid[] IS NULL OR r2.id = ANY($1))),0)
		FROM repositories r WHERE ($1::uuid[] IS NULL OR r.id = ANY($1))
		GROUP BY r.format ORDER BY r.format`, repoFilter(repoIDs))
	if err != nil {
		return nil, mapErr(err, "inventory")
	}
	defer rows.Close()
	var out []FormatInventory
	for rows.Next() {
		var f FormatInventory
		if err := rows.Scan(&f.Format, &f.Repositories, &f.Components, &f.Assets, &f.TotalBytes); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ScanSummary counts components by scan state (plus quarantined).
func (s *Store) ScanSummary(ctx context.Context, repoIDs []string) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT scan_state, count(*), count(*) FILTER (WHERE quarantined)
		FROM components WHERE ($1::uuid[] IS NULL OR repository_id = ANY($1)) GROUP BY scan_state`, repoFilter(repoIDs))
	if err != nil {
		return nil, mapErr(err, "scan summary")
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var state string
		var n, q int64
		if err := rows.Scan(&state, &n, &q); err != nil {
			return nil, err
		}
		out[state] = n
		out["quarantined"] += q
	}
	return out, rows.Err()
}

// ActivityEvent is one download, upload or delete.
type ActivityEvent struct {
	ID           int64     `json:"id"`
	At           time.Time `json:"at"`
	RepositoryID string    `json:"-"`
	Repository   string    `json:"repository"`
	Format       string    `json:"format"`
	Kind         string    `json:"kind"`
	Path         string    `json:"path"`
	ComponentID  *string   `json:"componentId,omitempty"`
	Component    string    `json:"component,omitempty"`
	Actor        string    `json:"actor"`
	ActorKind    string    `json:"actorKind"`
	RemoteIP     string    `json:"remoteIp"`
	UserAgent    string    `json:"userAgent"`
	Bytes        int64     `json:"bytes"`
}

// InsertActivity stores events, skipping repositories deleted meanwhile.
func (s *Store) InsertActivity(ctx context.Context, evs []ActivityEvent) error {
	batch := &pgx.Batch{}
	for _, e := range evs {
		batch.Queue(`INSERT INTO activity_events (at, repository_id, kind, path, component_id, actor, actor_kind, remote_ip, user_agent, bytes)
			SELECT $1, r.id, $3, $4, (SELECT id FROM components WHERE id = $5::uuid), $6, $7, $8, $9, $10
			FROM repositories r WHERE r.id = $2`,
			e.At, e.RepositoryID, e.Kind, e.Path, e.ComponentID, e.Actor, e.ActorKind, e.RemoteIP, e.UserAgent, e.Bytes)
	}
	return mapErr(s.pool.SendBatch(ctx, batch).Close(), "insert activity")
}

// ActivityQuery filters activity events.
type ActivityQuery struct {
	RepositoryIDs []string // nil = all
	Kind          string
	Actor         string // substring
	Path          string // substring
	From, To      *time.Time
	BeforeID      int64
	Limit         int
}

func (s *Store) ListActivity(ctx context.Context, q ActivityQuery) ([]*ActivityEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	if q.BeforeID <= 0 {
		q.BeforeID = 1<<63 - 1
	}
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.at, r.name, r.format, e.kind, e.path, e.component_id,
		coalesce(c.name || '@' || c.version, ''), e.actor, e.actor_kind, e.remote_ip, e.user_agent, e.bytes
		FROM activity_events e JOIN repositories r ON r.id = e.repository_id
		LEFT JOIN components c ON c.id = e.component_id
		WHERE e.id < $1 AND ($2::uuid[] IS NULL OR e.repository_id = ANY($2))
		AND ($3 = '' OR e.kind = $3) AND ($4 = '' OR e.actor ILIKE '%' || $4 || '%')
		AND ($5 = '' OR e.path ILIKE '%' || $5 || '%')
		AND ($6::timestamptz IS NULL OR e.at >= $6) AND ($7::timestamptz IS NULL OR e.at < $7)
		ORDER BY e.id DESC LIMIT $8`,
		q.BeforeID, repoFilter(q.RepositoryIDs), q.Kind, escapeLike(q.Actor), escapeLike(q.Path), q.From, q.To, q.Limit)
	if err != nil {
		return nil, mapErr(err, "list activity")
	}
	defer rows.Close()
	out := []*ActivityEvent{}
	for rows.Next() {
		var e ActivityEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Repository, &e.Format, &e.Kind, &e.Path, &e.ComponentID, &e.Component,
			&e.Actor, &e.ActorKind, &e.RemoteIP, &e.UserAgent, &e.Bytes); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// AuditQuery filters audit events.
type AuditQuery struct {
	Actor, Action, Target string // substrings (action: prefix)
	From, To              *time.Time
	BeforeID              int64
	Limit                 int
}

func (s *Store) SearchAuditEvents(ctx context.Context, q AuditQuery) ([]*AuditEvent, error) {
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 100
	}
	if q.BeforeID <= 0 {
		q.BeforeID = 1<<63 - 1
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, actor, action, target, details, remote_ip FROM audit_events
		WHERE id < $1 AND ($2 = '' OR actor ILIKE '%' || $2 || '%') AND ($3 = '' OR action LIKE $3 || '%')
		AND ($4 = '' OR target ILIKE '%' || $4 || '%')
		AND ($5::timestamptz IS NULL OR at >= $5) AND ($6::timestamptz IS NULL OR at < $6)
		ORDER BY id DESC LIMIT $7`, q.BeforeID, escapeLike(q.Actor), escapeLike(q.Action), escapeLike(q.Target), q.From, q.To, q.Limit)
	if err != nil {
		return nil, mapErr(err, "search audit events")
	}
	defer rows.Close()
	out := []*AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Details, &e.RemoteIP); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
