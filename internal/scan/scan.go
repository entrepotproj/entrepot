// Package scan implements the component scanning pipeline (placeholder;
// implemented in Phase 2).
package scan

import (
	"context"
	"log/slog"

	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// Deps are the services the pipeline uses.
type Deps struct {
	Config  *config.Config
	Store   *store.Store
	Repos   *repo.Service
	Formats *format.Registry
	Secrets *secrets.Box
	URLs    httpx.URLs
	Logger  *slog.Logger
}

type Service struct {
	Deps
}

func New(d Deps) *Service { return &Service{Deps: d} }

// Attach registers repository hooks (enqueue on store, quarantine gate).
func (s *Service) Attach() {}

// Run starts workers and the rescan scheduler until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {}
