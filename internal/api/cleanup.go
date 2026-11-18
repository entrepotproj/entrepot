package api

import (
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
)

// Phase 2 stubs: implemented by the cleanup agent.

func (s *Server) ListCleanupPolicies(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) CreateCleanupPolicy(w http.ResponseWriter, r *http.Request) { notImplemented(w) }

func (s *Server) DeleteCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) GetCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) UpdateCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	notImplemented(w)
}

func (s *Server) PreviewCleanupPolicy(w http.ResponseWriter, r *http.Request, name string, params apigen.PreviewCleanupPolicyParams) {
	notImplemented(w)
}

func (s *Server) RunRepositoryCleanup(w http.ResponseWriter, r *http.Request, name string, params apigen.RunRepositoryCleanupParams) {
	notImplemented(w)
}
