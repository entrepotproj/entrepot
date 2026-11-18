// Command entrepot runs the Entrepot package repository server.
//
//	entrepot serve   [-config file]   run the server (default)
//	entrepot migrate [-config file]   apply database migrations and exit
//	entrepot gc      [-config file]   garbage-collect unreferenced blobs
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

	"github.com/geoffo-dev/package-repository/internal/api"
	"github.com/geoffo-dev/package-repository/internal/app"
	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/db"
)

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("ENTREPOT_CONFIG"), "path to config file (env ENTREPOT_CONFIG)")
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
