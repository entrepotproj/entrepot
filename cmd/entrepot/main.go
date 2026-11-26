// Command entrepot runs the Entrepot package repository server.
//
//	entrepot serve   [-config file]   run the server (default)
//	entrepot migrate [-config file]   apply database migrations and exit
//	entrepot gc      [-config file]   garbage-collect unreferenced blobs
//	entrepot scan-worker [-config file] [-health-addr :8081]  run scan workers only (no HTTP API)
//	entrepot check-config [-config file]  validate configuration and print it (secrets redacted)
//	entrepot version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/entrepotproj/entrepot/internal/api"
	"github.com/entrepotproj/entrepot/internal/app"
	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/db"
	"gopkg.in/yaml.v3"
)

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("ENTREPOT_CONFIG"), "path to config file (env ENTREPOT_CONFIG)")
	healthAddr := fs.String("health-addr", os.Getenv("ENTREPOT_SCAN_WORKER_ADDR"),
		"scan-worker: serve /healthz and /readyz on this address (env ENTREPOT_SCAN_WORKER_ADDR)")
	_ = fs.Parse(args)

	if cmd == "version" {
		fmt.Println(api.Version)
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	if cmd == "check-config" {
		printConfig(cfg)
		return
	}
	logger := newLogger(cfg.Log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "serve":
		err = serve(ctx, cfg, logger)
	case "migrate":
		err = migrate(ctx, cfg)
	case "gc":
		err = gc(ctx, cfg, logger)
	case "scan-worker":
		err = scanWorker(ctx, cfg, logger, *healthAddr)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func newLogger(c config.Log) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(c.Level))
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	a.RunBackground(ctx)

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       cfg.Server.ReadTimeout,
		IdleTimeout:       120 * time.Second,
	}
	// Downloads held for a scan verdict answer at once when draining.
	srv.RegisterOnShutdown(a.Scan.StopHolds)
	errCh := make(chan error, 1)
	go func() {
		logger.Info("entrepot listening", "addr", cfg.Server.Addr, "version", api.Version, "baseURL", cfg.Server.BaseURL)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(sctx)
}

func migrate(ctx context.Context, cfg *config.Config) error {
	pool, err := db.Open(ctx, cfg.Database.URL, 2)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.Migrate(ctx, pool)
}

func gc(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	n, err := a.Repos.GC(ctx, time.Hour)
	if err != nil {
		return err
	}
	logger.Info("gc complete", "removed", n)
	return nil
}

// scanWorker runs only the scanning pipeline (workers, rescan scheduler,
// lease reaper) against the configured database and blob stores. It runs
// scan.workers workers (at least one).
func scanWorker(ctx context.Context, cfg *config.Config, logger *slog.Logger, healthAddr string) error {
	if cfg.Scan.Workers < 1 {
		cfg.Scan.Workers = 1
	}
	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	if healthAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if err := a.Store.Ping(r.Context()); err != nil {
				http.Error(w, "database unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte("ready")) //nolint:errcheck
		})
		srv := &http.Server{Addr: healthAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("scan-worker health server", "err", err)
			}
		}()
		defer srv.Close()
	}
	logger.Info("entrepot scan worker starting", "workers", cfg.Scan.Workers, "version", api.Version)
	a.Scan.Run(ctx)
	logger.Info("scan worker stopped")
	return nil
}

func printConfig(cfg *config.Config) {
	c := *cfg
	redact := func(s string) string {
		if s == "" {
			return ""
		}
		return "<redacted>"
	}
	c.Auth.SessionSecret = redact(c.Auth.SessionSecret)
	c.Auth.BootstrapToken = redact(c.Auth.BootstrapToken)
	c.Auth.OIDC.ClientSecret = redact(c.Auth.OIDC.ClientSecret)
	c.Database.URL = redact(c.Database.URL)
	var stores []config.BlobStoreSpec
	for _, b := range c.BlobStores {
		if b.S3 != nil {
			s3 := map[string]string{}
			for k, v := range b.S3 {
				if k == "secretAccessKey" {
					v = redact(v)
				}
				s3[k] = v
			}
			b.S3 = s3
		}
		stores = append(stores, b)
	}
	c.BlobStores = stores
	out, _ := yaml.Marshal(c)
	fmt.Print(string(out))
	fmt.Fprintln(os.Stderr, "configuration is valid")
}
