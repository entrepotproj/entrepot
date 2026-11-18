// Package routing evaluates routing rules that restrict what proxy
// repositories fetch from their upstream (placeholder; implemented in Phase 2).
package routing

import (
	"context"

	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

type Service struct {
	Store *store.Store
}

func New(st *store.Store) *Service { return &Service{Store: st} }

// Allowed reports whether rp may fetch path from its upstream.
func (s *Service) Allowed(ctx context.Context, rp *repo.Repository, path string) bool { return true }
