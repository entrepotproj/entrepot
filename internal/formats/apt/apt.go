// Package apt implements apt repositories (placeholder; implemented in Phase 2).
package apt

import (
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
)

type Handler struct{ env *format.Env }

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "apt" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
