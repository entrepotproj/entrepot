// Package usage records per-repository usage statistics (requests,
// downloads, uploads, bytes, proxy cache hits) for the dashboard.
//
// Counters are aggregated in memory per replica and flushed every few
// seconds as additive upserts into minute and hour buckets, so any number
// of replicas can record concurrently. Prometheus counters are updated at
// the same time for scraping.
package usage

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/store"
)

var (
	promRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "entrepot_repository_requests_total", Help: "Requests per repository and status class.",
	}, []string{"repository", "format", "status"})
	promDownloadBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "entrepot_repository_download_bytes_total", Help: "Bytes served per repository.",
	}, []string{"repository", "format"})
	promUploadBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "entrepot_repository_upload_bytes_total", Help: "Bytes uploaded per repository.",
	}, []string{"repository", "format"})
	promCache = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "entrepot_proxy_cache_total", Help: "Proxy cache lookups per repository by result (hit|miss).",
	}, []string{"repository", "result"})
)

// Repo identifies the repository an event belongs to.
type Repo struct {
	ID, Name, Format string
}

type counts struct {
	Requests, Errors, Downloads, Uploads, BytesOut, BytesIn, CacheHits, CacheMisses int64
}

type key struct {
	repoID string
	minute time.Time
}

// Recorder aggregates usage events. The zero value is not usable; use New.
// All methods are safe on a nil *Recorder (no-ops).
type Recorder struct {
	store  *store.Store
	logger *slog.Logger
	now    func() time.Time
	// RecordDownloads adds downloads to the activity log.
	RecordDownloads bool
	// Retention of activity events.
	Retention time.Duration

	mu       sync.Mutex
	cur      map[key]*counts
	activity []store.ActivityEvent
}

func New(st *store.Store, logger *slog.Logger) *Recorder {
	return &Recorder{store: st, logger: logger, now: time.Now, cur: map[key]*counts{},
		RecordDownloads: true, Retention: 30 * 24 * time.Hour}
}

// Asset identifies the artifact of an activity event.
type Asset struct {
	Path        string
	ComponentID *string
	Bytes       int64
}

func (r *Recorder) event(ctx context.Context, rp Repo, kind string, a Asset) {
	p := auth.FromContext(ctx)
	ri := httpx.RequestInfoFrom(ctx)
	ev := store.ActivityEvent{
		At: r.now().UTC(), RepositoryID: rp.ID, Kind: kind, Path: a.Path, ComponentID: a.ComponentID,
		Actor: p.Name, ActorKind: string(p.Kind), RemoteIP: ri.RemoteIP, UserAgent: ri.UserAgent, Bytes: a.Bytes,
	}
	r.mu.Lock()
	if len(r.activity) < 100000 { // bound memory if the database is unavailable
		r.activity = append(r.activity, ev)
	}
	r.mu.Unlock()
}

func (r *Recorder) add(repoID string, f func(c *counts)) {
	if r == nil || repoID == "" {
		return
	}
	k := key{repoID: repoID, minute: r.now().UTC().Truncate(time.Minute)}
	r.mu.Lock()
	c := r.cur[k]
	if c == nil {
		c = &counts{}
		r.cur[k] = c
	}
	f(c)
	r.mu.Unlock()
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// Request records a client request to a repository endpoint.
func (r *Recorder) Request(rp Repo, status int) {
	if r == nil {
		return
	}
	promRequests.WithLabelValues(rp.Name, rp.Format, statusClass(status)).Inc()
	r.add(rp.ID, func(c *counts) {
		c.Requests++
		if status >= 500 {
			c.Errors++
		}
	})
}

// Download records served artifact content.
func (r *Recorder) Download(ctx context.Context, rp Repo, a Asset) {
	if r == nil {
		return
	}
	promDownloadBytes.WithLabelValues(rp.Name, rp.Format).Add(float64(a.Bytes))
	r.add(rp.ID, func(c *counts) { c.Downloads++; c.BytesOut += a.Bytes })
	if r.RecordDownloads {
		r.event(ctx, rp, "download", a)
	}
}

// Upload records content stored by a client (not proxy caching).
func (r *Recorder) Upload(ctx context.Context, rp Repo, a Asset) {
	if r == nil {
		return
	}
	promUploadBytes.WithLabelValues(rp.Name, rp.Format).Add(float64(a.Bytes))
	r.add(rp.ID, func(c *counts) { c.Uploads++; c.BytesIn += a.Bytes })
	r.event(ctx, rp, "upload", a)
}

// Delete records a deleted asset.
func (r *Recorder) Delete(ctx context.Context, rp Repo, a Asset) {
	if r == nil {
		return
	}
	r.event(ctx, rp, "delete", a)
}

// CacheHit / CacheMiss record proxy cache lookups.
func (r *Recorder) CacheHit(rp Repo) {
	if r == nil {
		return
	}
	promCache.WithLabelValues(rp.Name, "hit").Inc()
	r.add(rp.ID, func(c *counts) { c.CacheHits++ })
}

func (r *Recorder) CacheMiss(rp Repo) {
	if r == nil {
		return
	}
	promCache.WithLabelValues(rp.Name, "miss").Inc()
	r.add(rp.ID, func(c *counts) { c.CacheMisses++ })
}

// Flush writes buffered counters to Postgres.
func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	pending := r.cur
	r.cur = map[key]*counts{}
	events := r.activity
	r.activity = nil
	r.mu.Unlock()
	if len(events) > 0 {
		if err := r.store.InsertActivity(ctx, events); err != nil {
			r.logger.Warn("activity flush", "err", err, "dropped", len(events))
		}
	}
	if len(pending) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for k, c := range pending {
		for _, table := range []string{"usage_minute", "usage_hour"} {
			bucket := k.minute
			if table == "usage_hour" {
				bucket = k.minute.Truncate(time.Hour)
			}
			// INSERT ... SELECT skips repositories deleted meanwhile.
			batch.Queue(`INSERT INTO `+table+` (bucket, repository_id, requests, errors, downloads, uploads,
				bytes_out, bytes_in, cache_hits, cache_misses)
				SELECT $1, id, $3, $4, $5, $6, $7, $8, $9, $10 FROM repositories WHERE id = $2
				ON CONFLICT (bucket, repository_id) DO UPDATE SET
					requests = `+table+`.requests + EXCLUDED.requests,
					errors = `+table+`.errors + EXCLUDED.errors,
					downloads = `+table+`.downloads + EXCLUDED.downloads,
					uploads = `+table+`.uploads + EXCLUDED.uploads,
					bytes_out = `+table+`.bytes_out + EXCLUDED.bytes_out,
					bytes_in = `+table+`.bytes_in + EXCLUDED.bytes_in,
					cache_hits = `+table+`.cache_hits + EXCLUDED.cache_hits,
					cache_misses = `+table+`.cache_misses + EXCLUDED.cache_misses`,
				bucket, k.repoID, c.Requests, c.Errors, c.Downloads, c.Uploads, c.BytesOut, c.BytesIn, c.CacheHits, c.CacheMisses)
		}
	}
	return r.store.Pool().SendBatch(ctx, batch).Close()
}

// Run flushes periodically and prunes old buckets until ctx is cancelled.
func (r *Recorder) Run(ctx context.Context, every time.Duration) {
	if r == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = r.Flush(fctx)
			cancel()
			return
		case <-t.C:
		}
		if err := r.Flush(ctx); err != nil {
			r.logger.Warn("usage flush", "err", err)
		}
		if time.Since(lastPrune) > time.Hour {
			lastPrune = time.Now()
			if _, err := r.store.Pool().Exec(ctx, `DELETE FROM usage_minute WHERE bucket < now() - interval '2 days'`); err != nil {
				r.logger.Warn("usage prune", "err", err)
			}
			if _, err := r.store.Pool().Exec(ctx, `DELETE FROM usage_hour WHERE bucket < now() - interval '400 days'`); err != nil {
				r.logger.Warn("usage prune", "err", err)
			}
			if r.Retention > 0 {
				if _, err := r.store.Pool().Exec(ctx, `DELETE FROM activity_events WHERE at < now() - make_interval(secs => $1)`,
					r.Retention.Seconds()); err != nil {
					r.logger.Warn("activity prune", "err", err)
				}
			}
		}
	}
}
