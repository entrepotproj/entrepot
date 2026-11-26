// Package app assembles an Entrepot instance from configuration.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entrepotproj/entrepot/internal/api"
	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/cleanup"
	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/db"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/formats/apt"
	"github.com/entrepotproj/entrepot/internal/formats/docker"
	"github.com/entrepotproj/entrepot/internal/formats/helm"
	"github.com/entrepotproj/entrepot/internal/formats/npm"
	"github.com/entrepotproj/entrepot/internal/formats/pypi"
	"github.com/entrepotproj/entrepot/internal/formats/raw"
	"github.com/entrepotproj/entrepot/internal/formats/yum"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/routing"
	"github.com/entrepotproj/entrepot/internal/scan"
	"github.com/entrepotproj/entrepot/internal/secrets"
	"github.com/entrepotproj/entrepot/internal/server"
	"github.com/entrepotproj/entrepot/internal/signing"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
	"github.com/entrepotproj/entrepot/internal/usage"
	"github.com/entrepotproj/entrepot/web"
)

type App struct {
	Config  *config.Config
	Pool    *pgxpool.Pool
	Store   *store.Store
	Repos   *repo.Service
	Env     *format.Env
	Formats *format.Registry
	Server  *server.Server
	Logger  *slog.Logger
	Secrets *secrets.Box
	Scan    *scan.Service
	Cleanup *cleanup.Service
	Routing *routing.Service
	Usage   *usage.Recorder
}

// New connects to the database, runs migrations (if enabled) and builds all
// services. It does not start listening.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*App, error) {
	pool, err := db.Open(ctx, cfg.Database.URL, cfg.Database.MaxConns)
	if err != nil {
		return nil, err
	}
	if cfg.Database.AutoMigrate {
		if err := db.Migrate(ctx, pool); err != nil {
			pool.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	st := store.New(pool)
	box, err := secrets.New(cfg.SecretsKey(), cfg.Secrets.PreviousKeys...)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("secrets: %w", err)
	}
	blobs := storage.NewRegistry(cfg.Storage.AllowedRoots, cfg.Storage.TempDir)
	blobs.Open = box.Open
	repos := repo.NewService(st, blobs, logger)
	repos.Secrets = box
	rec := usage.New(st, logger)
	rec.RecordDownloads = cfg.Usage.RecordDownloads
	rec.Retention = cfg.Usage.ActivityRetention
	repos.Usage = rec
	authn, err := auth.NewAuthenticator(cfg, st, logger)
	if err != nil {
		pool.Close()
		return nil, err
	}
	az := authz.New(st, cfg, logger)
	urls := httpx.URLs{Base: cfg.Server.BaseURL, TrustForwarded: cfg.Server.TrustForwardedHeaders}
	env := &format.Env{
		Config:  cfg,
		Repos:   repos,
		Proxy:   proxy.NewCache(repos, cfg.Proxy.Timeout, cfg.Proxy.UserAgent, logger),
		Auth:    authn,
		Authz:   az,
		URLs:    urls,
		Logger:  logger,
		Secrets: box,
		Signing: signing.New(st, box),
	}
	routes := routing.New(st)
	env.Proxy.Allow = routes.Allowed
	env.Proxy.Usage = rec
	formats := format.NewRegistry(
		raw.New(env),
		pypi.New(env),
		npm.New(env),
		docker.New(env),
		apt.New(env),
		yum.New(env),
		helm.New(env),
	)
	scanner := scan.New(scan.Deps{Config: cfg, Store: st, Repos: repos, Formats: formats, Secrets: box, URLs: urls, Logger: logger})
	scanner.Attach()
	cleaner := cleanup.New(cleanup.Deps{Store: st, Repos: repos, Formats: formats, Logger: logger})
	a := &App{Config: cfg, Pool: pool, Store: st, Repos: repos, Env: env, Formats: formats, Logger: logger,
		Scan: scanner, Cleanup: cleaner, Routing: routes, Usage: rec}
	a.Server = &server.Server{
		Env:     env,
		Store:   st,
		Formats: formats,
		UI:      web.Dist(),
		Logger:  logger,
		Usage:   rec,
		API: &api.Server{
			Config: cfg, Store: st, Repos: repos, Blobs: blobs, Auth: authn, Authz: az,
			Formats: formats, URLs: urls, Logger: logger, Secrets: box,
			Signing: env.Signing, Scan: scanner, Cleanup: cleaner, Routing: routes, Usage: rec,
		},
	}
	a.Secrets = box
	if err := a.resealSecrets(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("re-seal secrets: %w", err)
	}
	if err := a.bootstrap(ctx, blobs); err != nil {
		pool.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) Handler() http.Handler { return a.Server.Handler() }

func (a *App) Close() { a.Pool.Close() }

// RunBackground starts maintenance loops until ctx is cancelled.
func (a *App) RunBackground(ctx context.Context) {
	go a.Repos.RunMaintenance(ctx, 15*time.Minute, a.Logger)
	go a.Scan.Run(ctx)
	go a.backfillRaw(ctx)
	go a.Cleanup.Run(ctx, a.Config.Cleanup.Interval)
	flush := a.Config.Usage.FlushInterval
	if flush <= 0 {
		flush = 10 * time.Second
	}
	go a.Usage.Run(ctx, flush)
}

// backfillRaw links the files of raw repositories with scanning enabled to
// components (files stored before scanning was enabled, or before raw files
// were scannable).
func (a *App) backfillRaw(ctx context.Context) {
	list, err := a.Store.ListRepositories(ctx)
	if err != nil {
		a.Logger.Warn("raw backfill: list repositories", "err", err)
		return
	}
	for _, r := range list {
		if r.Format != "raw" || r.Kind == repo.KindGroup {
			continue
		}
		rp, err := a.Repos.Get(ctx, r.Name)
		if err != nil {
			continue
		}
		if _, err := a.Scan.BackfillRaw(ctx, rp); err != nil && ctx.Err() == nil {
			a.Logger.Warn("raw backfill", "repository", r.Name, "err", err)
		}
	}
}

// bootstrap creates blob stores declared in configuration, or a "default"
// file store when none exist at all.
func (a *App) bootstrap(ctx context.Context, blobs *storage.Registry) error {
	for _, spec := range a.Config.BlobStores {
		var cfg json.RawMessage
		var err error
		switch spec.Type {
		case "file":
			cfg, err = json.Marshal(storage.FileConfig{Path: spec.Path})
		case "s3":
			cfg, err = json.Marshal(spec.S3)
		default:
			return fmt.Errorf("blobStores[%s]: unknown type %q", spec.Name, spec.Type)
		}
		if err != nil {
			return err
		}
		// Normalise S3 config through the typed struct (bool fields, etc.).
		if spec.Type == "s3" {
			var sc storage.S3Config
			raw, _ := json.Marshal(spec.S3)
			if err := json.Unmarshal(normaliseS3(raw), &sc); err != nil {
				return fmt.Errorf("blobStores[%s]: %w", spec.Name, err)
			}
			if sc.SecretAccessKey, err = a.Secrets.Seal(sc.SecretAccessKey); err != nil {
				return err
			}
			cfg, _ = json.Marshal(sc)
		}
		if _, err := blobs.Build(ctx, spec.Type, cfg); err != nil {
			return fmt.Errorf("blobStores[%s]: %w", spec.Name, err)
		}
		if _, err := a.Store.UpsertBlobStore(ctx, &store.BlobStore{Name: spec.Name, Type: spec.Type, Config: cfg}); err != nil {
			return err
		}
		a.Logger.Info("blob store configured", "name", spec.Name, "type", spec.Type)
	}
	existing, err := a.Store.ListBlobStores(ctx)
	if err != nil {
		return err
	}
	if len(existing) == 0 && len(a.Config.Storage.AllowedRoots) > 0 {
		p := filepath.Join(a.Config.Storage.AllowedRoots[0], "default")
		if err := os.MkdirAll(p, 0o750); err != nil {
			a.Logger.Warn("could not create default blob store", "path", p, "err", err)
			return nil
		}
		cfg, _ := json.Marshal(storage.FileConfig{Path: p})
		if _, err := a.Store.CreateBlobStore(ctx, &store.BlobStore{Name: "default", Type: "file", Config: cfg}); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
		a.Logger.Info("created default file blob store", "path", p)
	}
	return nil
}

// normaliseS3 converts string booleans from YAML/env ("true") to JSON booleans.
func normaliseS3(raw []byte) []byte {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	for _, k := range []string{"forcePathStyle", "redirectDownloads"} {
		if v, ok := m[k].(string); ok {
			m[k] = v == "true"
		}
	}
	out, _ := json.Marshal(m)
	return out
}

// resealSecrets encrypts secrets that are still stored in plaintext (from
// before encryption was introduced) or with a previous key. It is
// idempotent and runs at every start.
func (a *App) resealSecrets(ctx context.Context) error {
	repos, err := a.Store.ListRepositories(ctx)
	if err != nil {
		return err
	}
	for _, r := range repos {
		var cfg map[string]json.RawMessage
		if json.Unmarshal(r.Config, &cfg) != nil || cfg["proxy"] == nil {
			continue
		}
		var px map[string]any
		if json.Unmarshal(cfg["proxy"], &px) != nil {
			continue
		}
		pw, _ := px["password"].(string)
		if !a.Secrets.NeedsReseal(pw) {
			continue
		}
		if px["password"], err = a.Secrets.Reseal(pw); err != nil {
			return fmt.Errorf("repository %s: %w", r.Name, err)
		}
		cfg["proxy"], _ = json.Marshal(px)
		r.Config, _ = json.Marshal(cfg)
		if _, err := a.Store.UpdateRepository(ctx, r); err != nil {
			return err
		}
		a.Logger.Info("sealed stored secret", "repository", r.Name)
	}
	stores, err := a.Store.ListBlobStores(ctx)
	if err != nil {
		return err
	}
	for _, b := range stores {
		if b.Type != "s3" {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b.Config, &m) != nil {
			continue
		}
		key, _ := m["secretAccessKey"].(string)
		if !a.Secrets.NeedsReseal(key) {
			continue
		}
		if m["secretAccessKey"], err = a.Secrets.Reseal(key); err != nil {
			return fmt.Errorf("blob store %s: %w", b.Name, err)
		}
		raw, _ := json.Marshal(m)
		if _, err := a.Store.UpdateBlobStore(ctx, b.Name, raw); err != nil {
			return err
		}
		a.Logger.Info("sealed stored secret", "blobStore", b.Name)
	}
	scanners, err := a.Store.ListScanners(ctx)
	if err != nil {
		return err
	}
	for _, sc := range scanners {
		cfg, err := scan.ParseScannerConfig(sc.Config)
		if err != nil {
			continue
		}
		changed, err := cfg.Reseal(a.Secrets)
		if err != nil {
			return fmt.Errorf("scanner %s: %w", sc.Name, err)
		}
		if !changed {
			continue
		}
		if sc.Config, err = json.Marshal(cfg); err != nil {
			return err
		}
		if _, err := a.Store.UpdateScanner(ctx, sc); err != nil {
			return err
		}
		a.Logger.Info("sealed stored secret", "scanner", sc.Name)
	}
	return nil
}
