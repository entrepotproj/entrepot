package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Component struct {
	ID           string          `json:"id"`
	RepositoryID string          `json:"repositoryId"`
	Repository   string          `json:"repository"`
	Format       string          `json:"format"`
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Attrs        json.RawMessage `json:"attrs"`
	CreatedAt    time.Time       `json:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
	// ScanState is unscanned, pending, clean, vulnerable, error or unsupported.
	ScanState   string     `json:"scanState"`
	Quarantined bool       `json:"quarantined"`
	ScannedAt   *time.Time `json:"scannedAt,omitempty"`
}

type Asset struct {
	ID               string          `json:"id"`
	RepositoryID     string          `json:"repositoryId"`
	Repository       string          `json:"repository"`
	ComponentID      *string         `json:"componentId,omitempty"`
	Path             string          `json:"path"`
	Digest           string          `json:"digest"`
	Size             int64           `json:"size"`
	ContentType      string          `json:"contentType"`
	Attrs            json.RawMessage `json:"attrs"`
	CreatedBy        string          `json:"createdBy"`
	CreatedAt        time.Time       `json:"createdAt"`
	UpdatedAt        time.Time       `json:"updatedAt"`
	CachedAt         *time.Time      `json:"cachedAt,omitempty"`
	LastDownloadedAt *time.Time      `json:"lastDownloadedAt,omitempty"`
	// Uploader describes who stored the asset (kind, name and, for GitLab
	// CI jobs, project/pipeline/commit claims).
	Uploader json.RawMessage `json:"uploader,omitempty"`
}

const assetSelect = `SELECT a.id, a.repository_id, r.name, a.component_id, a.path, a.digest, a.size,
	a.content_type, a.attrs, a.created_by, a.created_at, a.updated_at, a.cached_at, a.last_downloaded_at, a.uploader
	FROM assets a JOIN repositories r ON r.id = a.repository_id`

func scanAsset(row interface{ Scan(...any) error }) (*Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.RepositoryID, &a.Repository, &a.ComponentID, &a.Path, &a.Digest, &a.Size,
		&a.ContentType, &a.Attrs, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt, &a.CachedAt, &a.LastDownloadedAt, &a.Uploader)
	return &a, err
}

func collectAssets(rows pgx.Rows, err error) ([]*Asset, error) {
	if err != nil {
		return nil, mapErr(err, "query assets")
	}
	defer rows.Close()
	out := []*Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAsset(ctx context.Context, repoID, path string) (*Asset, error) {
	a, err := scanAsset(s.pool.QueryRow(ctx, assetSelect+` WHERE a.repository_id=$1 AND a.path=$2`, repoID, path))
	return a, mapErr(err, "asset "+path)
}

func (s *Store) GetAssetByID(ctx context.Context, id string) (*Asset, error) {
	a, err := scanAsset(s.pool.QueryRow(ctx, assetSelect+` WHERE a.id=$1`, id))
	return a, mapErr(err, "asset "+id)
}

// ListAssets lists assets whose path starts with prefix, ordered by path,
// starting after the `after` path (keyset pagination).
func (s *Store) ListAssets(ctx context.Context, repoID, prefix, after string, limit int) ([]*Asset, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	return collectAssets(s.pool.Query(ctx, assetSelect+`
		WHERE a.repository_id=$1 AND a.path LIKE $2 AND a.path > $3 ORDER BY a.path LIMIT $4`,
		repoID, likePrefix(prefix), after, limit))
}

func (s *Store) ListComponentAssets(ctx context.Context, componentID string) ([]*Asset, error) {
	return collectAssets(s.pool.Query(ctx, assetSelect+` WHERE a.component_id=$1 ORDER BY a.path`, componentID))
}

// BrowseEntry is a single child of a directory in the repository tree.
type BrowseEntry struct {
	Name    string  `json:"name"`
	Path    string  `json:"path"`
	IsDir   bool    `json:"isDir"`
	AssetID *string `json:"assetId,omitempty"`
	Size    int64   `json:"size"`
}

// Browse lists the immediate children of dir (which must be "" or end in "/").
func (s *Store) Browse(ctx context.Context, repoID, dir string, limit int) ([]BrowseEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		WITH children AS (
			SELECT a.id, a.size,
			       split_part(substr(a.path, length($2::text)+1), '/', 1) AS name,
			       position('/' in substr(a.path, length($2::text)+1)) > 0 AS is_dir
			FROM assets a WHERE a.repository_id=$1 AND a.path LIKE $3
		)
		SELECT name, is_dir,
		       CASE WHEN NOT is_dir THEN min(id::text) END AS asset_id,
		       sum(size)::bigint
		FROM children
		GROUP BY name, is_dir
		ORDER BY is_dir DESC, name
		LIMIT $4`, repoID, dir, likePrefix(dir), limit)
	if err != nil {
		return nil, mapErr(err, "browse")
	}
	defer rows.Close()
	out := []BrowseEntry{}
	for rows.Next() {
		var e BrowseEntry
		if err := rows.Scan(&e.Name, &e.IsDir, &e.AssetID, &e.Size); err != nil {
			return nil, err
		}
		e.Path = dir + e.Name
		if e.IsDir {
			e.Path += "/"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PutAssetParams describes an asset write. The blob must already be stored
// in the repository's blob store.
type PutAssetParams struct {
	RepositoryID string
	StoreID      string
	Path         string
	Digest       string
	Size         int64
	ContentType  string
	Attrs        json.RawMessage
	CreatedBy    string
	ComponentID  *string
	// Cached marks proxy content (sets cached_at = now()).
	Cached bool
	// NoOverwrite fails with ErrConflict if an asset already exists at Path
	// with different content.
	NoOverwrite bool
	// Uploader is recorded when the content changes (JSON object).
	Uploader json.RawMessage
}

// PutAsset inserts or replaces the asset at (repository, path) and maintains
// blob reference counts. It returns the stored asset.
func (s *Store) PutAsset(ctx context.Context, p PutAssetParams) (*Asset, error) {
	if p.Attrs == nil {
		p.Attrs = json.RawMessage(`{}`)
	}
	if p.ContentType == "" {
		p.ContentType = "application/octet-stream"
	}
	if p.Uploader == nil {
		p.Uploader = json.RawMessage(`{}`)
	}
	var id string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var oldID, oldDigest string
		err := tx.QueryRow(ctx, `SELECT id, digest FROM assets WHERE repository_id=$1 AND path=$2 FOR UPDATE`,
			p.RepositoryID, p.Path).Scan(&oldID, &oldDigest)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists && oldDigest != p.Digest && p.NoOverwrite {
			return ErrConflict
		}
		if !exists || oldDigest != p.Digest {
			if _, err := tx.Exec(ctx, `INSERT INTO blobs (store_id, digest, size, refcount) VALUES ($1,$2,$3,1)
				ON CONFLICT (store_id, digest) DO UPDATE SET refcount = blobs.refcount + 1, updated_at=now()`,
				p.StoreID, p.Digest, p.Size); err != nil {
				return err
			}
		}
		if exists && oldDigest != p.Digest {
			if _, err := tx.Exec(ctx, `UPDATE blobs SET refcount = refcount - 1, updated_at=now() WHERE store_id=$1 AND digest=$2`,
				p.StoreID, oldDigest); err != nil {
				return err
			}
		}
		if exists {
			id = oldID
			_, err = tx.Exec(ctx, `UPDATE assets SET digest=$2, size=$3, content_type=$4, attrs=$5,
				component_id=coalesce($6, component_id), updated_at=now(),
				cached_at = CASE WHEN $7 THEN now() ELSE cached_at END,
				uploader = CASE WHEN digest = $2 THEN uploader ELSE $9 END,
				created_by = CASE WHEN digest = $2 THEN created_by ELSE $8 END
				WHERE id=$1`, oldID, p.Digest, p.Size, p.ContentType, p.Attrs, p.ComponentID, p.Cached, p.CreatedBy, p.Uploader)
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO assets (repository_id, component_id, path, digest, size, content_type,
			attrs, created_by, cached_at, uploader) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, CASE WHEN $9 THEN now() END, $10) RETURNING id`,
			p.RepositoryID, p.ComponentID, p.Path, p.Digest, p.Size, p.ContentType, p.Attrs, p.CreatedBy, p.Cached, p.Uploader).Scan(&id)
	})
	if err != nil {
		return nil, mapErr(err, "put asset "+p.Path)
	}
	return s.GetAssetByID(ctx, id)
}

// TouchCached marks a proxied asset as revalidated now.
func (s *Store) TouchCached(ctx context.Context, assetID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE assets SET cached_at=now() WHERE id=$1`, assetID)
	return mapErr(err, "touch asset")
}

// MarkDownloaded records a download (best effort, coarse-grained to limit writes).
func (s *Store) MarkDownloaded(ctx context.Context, assetID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE assets SET last_downloaded_at=now()
		WHERE id=$1 AND (last_downloaded_at IS NULL OR last_downloaded_at < now() - interval '1 hour')`, assetID)
	return mapErr(err, "mark downloaded")
}

// DeleteAsset deletes an asset and decrements its blob refcount. Components
// left without assets are deleted too.
func (s *Store) DeleteAsset(ctx context.Context, id string) (*Asset, error) {
	a, err := s.GetAssetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var storeID string
		if err := tx.QueryRow(ctx, `SELECT blob_store_id FROM repositories WHERE id=$1`, a.RepositoryID).Scan(&storeID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM assets WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		if _, err := tx.Exec(ctx, `UPDATE blobs SET refcount = refcount - 1, updated_at=now() WHERE store_id=$1 AND digest=$2`,
			storeID, a.Digest); err != nil {
			return err
		}
		if a.ComponentID != nil {
			_, err = tx.Exec(ctx, `DELETE FROM components c WHERE c.id=$1
				AND NOT EXISTS (SELECT 1 FROM assets WHERE component_id=c.id)`, *a.ComponentID)
		}
		return err
	})
	return a, mapErr(err, "delete asset")
}

// DeleteAssetsByPrefix deletes all assets under prefix and returns them.
func (s *Store) DeleteAssetsByPrefix(ctx context.Context, repoID, prefix string) (int, error) {
	n := 0
	for {
		assets, err := s.ListAssets(ctx, repoID, prefix, "", 500)
		if err != nil {
			return n, err
		}
		if len(assets) == 0 {
			return n, nil
		}
		for _, a := range assets {
			if _, err := s.DeleteAsset(ctx, a.ID); err != nil && !errors.Is(err, ErrNotFound) {
				return n, err
			}
			n++
		}
	}
}

func (s *Store) UpsertComponent(ctx context.Context, repoID, name, version string, attrs json.RawMessage) (*Component, error) {
	if attrs == nil {
		attrs = json.RawMessage(`{}`)
	}
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO components (repository_id, name, version, attrs) VALUES ($1,$2,$3,$4)
		ON CONFLICT (repository_id, name, version) DO UPDATE SET attrs = components.attrs || EXCLUDED.attrs, updated_at=now()
		RETURNING id`, repoID, name, version, attrs).Scan(&id)
	if err != nil {
		return nil, mapErr(err, "upsert component")
	}
	return s.GetComponent(ctx, id)
}

const componentSelect = `SELECT c.id, c.repository_id, r.name, r.format, c.name, c.version, c.attrs, c.created_at, c.updated_at,
	c.scan_state, c.quarantined, c.scanned_at
	FROM components c JOIN repositories r ON r.id = c.repository_id`

func scanComponent(row interface{ Scan(...any) error }) (*Component, error) {
	var c Component
	err := row.Scan(&c.ID, &c.RepositoryID, &c.Repository, &c.Format, &c.Name, &c.Version, &c.Attrs, &c.CreatedAt, &c.UpdatedAt,
		&c.ScanState, &c.Quarantined, &c.ScannedAt)
	return &c, err
}

func (s *Store) GetComponent(ctx context.Context, id string) (*Component, error) {
	c, err := scanComponent(s.pool.QueryRow(ctx, componentSelect+` WHERE c.id=$1`, id))
	return c, mapErr(err, "component "+id)
}

func (s *Store) FindComponent(ctx context.Context, repoID, name, version string) (*Component, error) {
	c, err := scanComponent(s.pool.QueryRow(ctx, componentSelect+` WHERE c.repository_id=$1 AND c.name=$2 AND c.version=$3`,
		repoID, name, version))
	return c, mapErr(err, "component "+name+"@"+version)
}

type ComponentQuery struct {
	// RepositoryIDs restricts the search; nil means all repositories.
	RepositoryIDs []string
	Format        string
	// Name is a case-insensitive substring match.
	Name    string
	Version string
	// ScanState restricts to one scan state ("" for any).
	ScanState string
	// Quarantined restricts to quarantined (true) or other (false) components; nil for any.
	Quarantined *bool
	Limit       int
	Offset      int
}

func (s *Store) SearchComponents(ctx context.Context, q ComponentQuery) ([]*Component, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	sql := componentSelect + ` WHERE ($1::uuid[] IS NULL OR c.repository_id = ANY($1))
		AND ($2 = '' OR r.format = $2)
		AND ($3 = '' OR c.name ILIKE '%' || $3 || '%')
		AND ($4 = '' OR c.version = $4)
		AND ($7 = '' OR c.scan_state = $7)
		AND ($8::boolean IS NULL OR c.quarantined = $8)
		ORDER BY lower(c.name), c.created_at DESC LIMIT $5 OFFSET $6`
	var ids any
	if q.RepositoryIDs != nil {
		ids = q.RepositoryIDs
	}
	rows, err := s.pool.Query(ctx, sql, ids, q.Format, escapeLike(q.Name), q.Version, q.Limit, q.Offset, q.ScanState, q.Quarantined)
	if err != nil {
		return nil, mapErr(err, "search components")
	}
	defer rows.Close()
	out := []*Component{}
	for rows.Next() {
		c, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ListComponentsByName(ctx context.Context, repoID, name string) ([]*Component, error) {
	rows, err := s.pool.Query(ctx, componentSelect+` WHERE c.repository_id=$1 AND c.name=$2 ORDER BY c.created_at`, repoID, name)
	if err != nil {
		return nil, mapErr(err, "list components")
	}
	defer rows.Close()
	out := []*Component{}
	for rows.Next() {
		c, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListComponentNames returns the distinct component names in a repository.
func (s *Store) ListComponentNames(ctx context.Context, repoID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT name FROM components WHERE repository_id=$1 ORDER BY name`, repoID)
	if err != nil {
		return nil, mapErr(err, "list component names")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UnreferencedBlobs returns blobs with refcount <= 0 untouched for at least grace.
func (s *Store) UnreferencedBlobs(ctx context.Context, storeID string, grace time.Duration, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT digest FROM blobs WHERE store_id=$1 AND refcount <= 0
		AND updated_at < now() - make_interval(secs => $2) LIMIT $3`, storeID, grace.Seconds(), limit)
	if err != nil {
		return nil, mapErr(err, "unreferenced blobs")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteBlobRow removes a blob row if it is still unreferenced. Returns true
// when the row was deleted and the underlying object may be removed.
func (s *Store) DeleteBlobRow(ctx context.Context, storeID, digest string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM blobs WHERE store_id=$1 AND digest=$2 AND refcount <= 0`, storeID, digest)
	if err != nil {
		return false, mapErr(err, "delete blob")
	}
	return tag.RowsAffected() > 0, nil
}

// BlobKnown reports whether the store has a referenced (or recently
// ingested) row for digest. Used by Docker for cross-repository mounts.
func (s *Store) BlobKnown(ctx context.Context, storeID, digest string) (bool, int64, error) {
	var size int64
	err := s.pool.QueryRow(ctx, `SELECT size FROM blobs WHERE store_id=$1 AND digest=$2`, storeID, digest).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, nil
	}
	return err == nil, size, mapErr(err, "blob")
}

func likePrefix(p string) string { return escapeLike(p) + "%" }

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
