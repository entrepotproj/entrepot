package docker

import (
	"errors"
	"net/http"

	"github.com/entrepotproj/entrepot/internal/repo"
)

// hostRepo returns the Docker repository served on the request's own
// hostname (docker.host), or nil when the request addressed another host
// (the main host, where the first path segment names the repository).
func (h *Handler) hostRepo(r *http.Request) *repo.Repository {
	host := h.env.URLs.RequestHost(r)
	if host == "" || host == h.env.URLs.BaseHost() {
		return nil
	}
	rp, err := h.env.Repos.ByDockerHost(r.Context(), host)
	if err != nil {
		if !errors.Is(err, repo.ErrNotFound) {
			h.env.Logger.Warn("docker host lookup", "host", host, "err", err)
		}
		return nil
	}
	if rp.Format != h.Name() {
		return nil
	}
	return rp
}
