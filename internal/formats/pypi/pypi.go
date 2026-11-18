// Package pypi implements Python package repositories (placeholder).
package pypi

import (
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
)

type Handler struct{ env *format.Env }

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "pypi" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
