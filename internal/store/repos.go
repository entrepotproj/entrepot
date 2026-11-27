package store

import (
	"context"
	"encoding/json"
	"time"
)

type BlobStore struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

type BlobStoreUsage struct {
	BlobCount    int64 `json:"blobCount"`
	TotalBytes   int64 `json:"totalBytes"`
	Repositories int64 `json:"repositories"`
}

const blobStoreCols = `id, name, type, config, created_at, updated_at`

func scanBlobStore(row interface{ Scan(...any) error }) (*BlobStore, error) {
	var b BlobStore
	err := row.Scan(&b.ID, &b.Name, &b.Type, &b.Config, &b.CreatedAt, &b.UpdatedAt)
	return &b, err
}

func (s *Store) ListBlobStores(ctx context.Context) ([]*BlobStore, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+blobStoreCols+` FROM blob_stores ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list blob stores")
	}
	defer rows.Close()
	var out []*BlobStore
	for rows.Next() {
		b, err := scanBlobStore(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) GetBlobStore(ctx context.Context, name string) (*BlobStore, error) {
	b, err := scanBlobStore(s.pool.QueryRow(ctx, `SELECT `+blobStoreCols+` FROM blob_stores WHERE name=$1`, name))
	return b, mapErr(err, "blob store "+name)
}

func (s *Store) GetBlobStoreByID(ctx context.Context, id string) (*BlobStore, error) {
	b, err := scanBlobStore(s.pool.QueryRow(ctx, `SELECT `+blobStoreCols+` FROM blob_stores WHERE id=$1`, id))
	return b, mapErr(err, "blob store "+id)
}

func (s *Store) CreateBlobStore(ctx context.Context, b *BlobStore) (*BlobStore, error) {
	out, err := scanBlobStore(s.pool.QueryRow(ctx,
		`INSERT INTO blob_stores (name, type, config) VALUES ($1,$2,$3) RETURNING `+blobStoreCols,
		b.Name, b.Type, b.Config))
	return out, mapErr(err, "create blob store "+b.Name)
}

// UpsertBlobStore creates or updates a store by name (used for config bootstrap).
func (s *Store) UpsertBlobStore(ctx context.Context, b *BlobStore) (*BlobStore, error) {
	out, err := scanBlobStore(s.pool.QueryRow(ctx,
		`INSERT INTO blob_stores (name, type, config) VALUES ($1,$2,$3)
		 ON CONFLICT (name) DO UPDATE SET type=EXCLUDED.type, config=EXCLUDED.config, updated_at=now()
		 RETURNING `+blobStoreCols,
		b.Name, b.Type, b.Config))
	return out, mapErr(err, "upsert blob store "+b.Name)
}

func (s *Store) UpdateBlobStore(ctx context.Context, name string, config json.RawMessage) (*BlobStore, error) {
	out, err := scanBlobStore(s.pool.QueryRow(ctx,
		`UPDATE blob_stores SET config=$2, updated_at=now() WHERE name=$1 RETURNING `+blobStoreCols,
		name, config))
	return out, mapErr(err, "update blob store "+name)
}

func (s *Store) DeleteBlobStore(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM blob_stores WHERE name=$1`, name)
	if err != nil {
		return mapErr(err, "delete blob store "+name)
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "blob store "+name)
	}
	return nil
}

func (s *Store) BlobStoreUsage(ctx context.Context, id string) (BlobStoreUsage, error) {
	var u BlobStoreUsage
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM blobs WHERE store_id=$1),
		(SELECT coalesce(sum(size),0) FROM blobs WHERE store_id=$1),
		(SELECT count(*) FROM repositories WHERE blob_store_id=$1)`, id).Scan(&u.BlobCount, &u.TotalBytes, &u.Repositories)
	return u, mapErr(err, "blob store usage")
}

type Repository struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Format        string          `json:"format"`
	Kind          string          `json:"kind"`
	BlobStoreID   string          `json:"blobStoreId"`
	BlobStoreName string          `json:"blobStore"`
	Description   string          `json:"description"`
	Online        bool            `json:"online"`
	AnonymousRead bool            `json:"anonymousRead"`
	Config        json.RawMessage `json:"config"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

const repoSelect = `SELECT r.id, r.name, r.format, r.kind, r.blob_store_id, b.name, r.description,
	r.online, r.anonymous_read, r.config, r.created_at, r.updated_at
	FROM repositories r JOIN blob_stores b ON b.id = r.blob_store_id`

func scanRepo(row interface{ Scan(...any) error }) (*Repository, error) {
	var r Repository
	err := row.Scan(&r.ID, &r.Name, &r.Format, &r.Kind, &r.BlobStoreID, &r.BlobStoreName, &r.Description,
		&r.Online, &r.AnonymousRead, &r.Config, &r.CreatedAt, &r.UpdatedAt)
	return &r, err
}

func (s *Store) ListRepositories(ctx context.Context) ([]*Repository, error) {
	rows, err := s.pool.Query(ctx, repoSelect+` ORDER BY r.name`)
	if err != nil {
		return nil, mapErr(err, "list repositories")
	}
	defer rows.Close()
	var out []*Repository
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRepository(ctx context.Context, name string) (*Repository, error) {
	r, err := scanRepo(s.pool.QueryRow(ctx, repoSelect+` WHERE r.name=$1`, name))
	return r, mapErr(err, "repository "+name)
}

func (s *Store) GetRepositoryByID(ctx context.Context, id string) (*Repository, error) {
	r, err := scanRepo(s.pool.QueryRow(ctx, repoSelect+` WHERE r.id=$1`, id))
	return r, mapErr(err, "repository "+id)
}

func (s *Store) CreateRepository(ctx context.Context, r *Repository) (*Repository, error) {
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO repositories
		(name, format, kind, blob_store_id, description, online, anonymous_read, config)
		VALUES ($1,$2,$3,(SELECT id FROM blob_stores WHERE name=$4),$5,$6,$7,$8) RETURNING id`,
		r.Name, r.Format, r.Kind, r.BlobStoreName, r.Description, r.Online, r.AnonymousRead, r.Config).Scan(&id)
	if err != nil {
		if isNotNullViolation(err) {
			return nil, mapErr(errNoRows, "blob store "+r.BlobStoreName)
		}
		return nil, mapErr(err, "create repository "+r.Name)
	}
	return s.GetRepositoryByID(ctx, id)
}

// UpdateRepository updates mutable fields. Format, kind and blob store are
// immutable after creation (changing them would orphan content).
func (s *Store) UpdateRepository(ctx context.Context, r *Repository) (*Repository, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE repositories SET description=$2, online=$3, anonymous_read=$4,
		config=$5, updated_at=now() WHERE name=$1`,
		r.Name, r.Description, r.Online, r.AnonymousRead, r.Config)
	if err != nil {
		return nil, mapErr(err, "update repository "+r.Name)
	}
	if tag.RowsAffected() == 0 {
		return nil, mapErr(errNoRows, "repository "+r.Name)
	}
	return s.GetRepository(ctx, r.Name)
}

// DeleteRepository removes the repository and releases its blob references.
func (s *Store) DeleteRepository(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx pgxTx) error {
		var id, storeID string
		if err := tx.QueryRow(ctx, `SELECT id, blob_store_id FROM repositories WHERE name=$1 FOR UPDATE`, name).Scan(&id, &storeID); err != nil {
			return mapErr(err, "repository "+name)
		}
		if _, err := tx.Exec(ctx, `UPDATE blobs b SET refcount = b.refcount - a.n, updated_at=now()
			FROM (SELECT digest, count(*) AS n FROM assets WHERE repository_id=$1 GROUP BY digest) a
			WHERE b.store_id=$2 AND b.digest=a.digest`, id, storeID); err != nil {
			return mapErr(err, "release blobs")
		}
		_, err := tx.Exec(ctx, `DELETE FROM repositories WHERE id=$1`, id)
		return mapErr(err, "delete repository "+name)
	})
}

type RepositoryStats struct {
	Assets     int64 `json:"assets"`
	Components int64 `json:"components"`
	TotalBytes int64 `json:"totalBytes"`
}

func (s *Store) RepositoryStats(ctx context.Context, id string) (RepositoryStats, error) {
	var st RepositoryStats
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM assets WHERE repository_id=$1),
		(SELECT count(*) FROM components WHERE repository_id=$1),
		(SELECT coalesce(sum(size),0) FROM assets WHERE repository_id=$1)`, id).Scan(&st.Assets, &st.Components, &st.TotalBytes)
	return st, mapErr(err, "repository stats")
}

// RepositoryByDockerHost returns the name of the Docker repository whose
// docker.host is host, or ErrNotFound.
func (s *Store) RepositoryByDockerHost(ctx context.Context, host string) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM repositories
		WHERE format = 'docker' AND lower(config->'docker'->>'host') = lower($1)`, host).Scan(&name)
	return name, mapErr(err, "repository for host "+host)
}
