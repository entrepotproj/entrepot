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

	"github.com/geoffo-dev/package-repository/internal/api"
	"github.com/geoffo-dev/package-repository/internal/auth"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/db"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/formats/docker"
	"github.com/geoffo-dev/package-repository/internal/formats/npm"
	"github.com/geoffo-dev/package-repository/internal/formats/pypi"
	"github.com/geoffo-dev/package-repository/internal/formats/raw"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/server"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
	"github.com/geoffo-dev/package-repository/web"
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
	blobs := storage.NewRegistry(cfg.Storage.AllowedRoots, cfg.Storage.TempDir)
	repos := repo.NewService(st, blobs, logger)
	authn, err := auth.NewAuthenticator(cfg, st, logger)
	if err != nil {
		pool.Close()
		return nil, err
	}
	az := authz.New(st, cfg, logger)
	urls := httpx.URLs{Base: cfg.Server.BaseURL, TrustForwarded: cfg.Server.TrustForwardedHeaders}
	env := &format.Env{
		Config: cfg,
		Repos:  repos,
		Proxy:  proxy.NewCache(repos, cfg.Proxy.Timeout, cfg.Proxy.UserAgent, logger),
		Auth:   authn,
		Authz:  az,
		URLs:   urls,
		Logger: logger,
	}
	formats := format.NewRegistry(
		raw.New(env),
		pypi.New(env),
		npm.New(env),
		docker.New(env),
	)
	a := &App{Config: cfg, Pool: pool, Store: st, Repos: repos, Env: env, Formats: formats, Logger: logger}
	a.Server = &server.Server{
		Env:     env,
		Store:   st,
		Formats: formats,
		UI:      web.Dist(),
		Logger:  logger,
		API: &api.Server{
			Config: cfg, Store: st, Repos: repos, Blobs: blobs, Auth: authn, Authz: az,
			Formats: formats, URLs: urls, Logger: logger,
		},
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
