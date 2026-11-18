// Package signing manages per-repository OpenPGP signing keys for hosted
// Apt and Yum repositories (placeholder; implemented in Phase 2).
package signing

import (
	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// Service creates, rotates and uses repository signing keys.
type Service struct {
	Store   *store.Store
	Secrets *secrets.Box
}

func New(st *store.Store, box *secrets.Box) *Service { return &Service{Store: st, Secrets: box} }
