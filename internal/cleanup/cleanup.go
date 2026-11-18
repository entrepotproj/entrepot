// Package cleanup applies cleanup policies to repositories (placeholder;
// implemented in Phase 2).
package cleanup

import (
	"context"
	"log/slog"
	"time"

	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

type Deps struct {
	Store   *store.Store
	Repos   *repo.Service
	Formats *format.Registry
	Logger  *slog.Logger
}

type Service struct {
	Deps
}

func New(d Deps) *Service { return &Service{Deps: d} }

// Run applies policies every interval until ctx is cancelled (0 disables).
func (s *Service) Run(ctx context.Context, interval time.Duration) {}
