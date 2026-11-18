// Package pypi implements Python package repositories (the "simple"
// repository API of PEP 503 / PEP 691 plus the legacy upload API used by
// twine).
//
// URL layout below /repository/{repo}/:
//
//	GET    simple/                                  project index (HTML or JSON)
//	GET    simple/{project}/                        project page (HTML or JSON)
//	GET    packages/{project}/{version}/{filename}  distribution file
//	GET    packages/{project}/{version}/{filename}.metadata  PEP 658 core metadata
//	POST   /  (or legacy/)                          twine upload (:action=file_upload)
//	DELETE packages/{project}/[{version}/[{filename}]]  delete files (hosted, or cached proxy content)
//	DELETE simple/{project}                         drop a cached upstream index (proxy)
//
// Links in simple pages are relative ("../../packages/..."), so they resolve
// against whatever host and credentials the client used for the index.
//
// Hosted repositories store files at packages/{project}/{version}/{filename}
// with {project} normalised per PEP 503. Proxy repositories cache the
// upstream project page verbatim at simple/{project} and rewrite its file
// links at serve time to the same packages/... layout; a file request is
// mapped back to the upstream URL recorded in the cached page. Group
// repositories merge the project pages of their members (first member wins
// for a given filename) and serve files from the first member that has them.
package pypi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
)

// MaxUpload is the largest accepted distribution upload (2 GiB).
const MaxUpload = 2 << 30

type Handler struct{ env *format.Env }

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "pypi" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

// ValidateRepository checks proxy configuration.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind == repo.KindProxy && cfg.Proxy != nil {
		u, err := url.Parse(cfg.Proxy.RemoteURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return format.BadRequest("proxy.remoteUrl must be an http(s) URL, e.g. https://pypi.org")
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	unescaped, err := url.PathUnescape(p)
	if err != nil {
		http.Error(w, "invalid path encoding", http.StatusBadRequest)
		return
	}
	clean, err := format.CleanPath(unescaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.env.Authorize(w, r, rp, authz.Read) {
			return
		}
		h.get(w, r, rp, clean)
	case http.MethodPost:
		if clean != "" && strings.TrimSuffix(clean, "/") != "legacy" {
			http.NotFound(w, r)
			return
		}
		if !rp.IsHosted() {
			http.Error(w, "uploads are only accepted by hosted repositories", http.StatusMethodNotAllowed)
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Write) {
			return
		}
		h.legacyUpload(w, r, rp)
	case http.MethodDelete:
		if rp.IsGroup() {
			http.Error(w, "group repositories are read-only", http.StatusMethodNotAllowed)
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Delete) {
			return
		}
		h.delete(w, r, rp, clean)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) repoURL(r *http.Request, rp *repo.Repository) string {
	return h.env.URLs.BaseURL(r) + "/repository/" + url.PathEscape(rp.Name) + "/"
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, rp *repo.Repository, rel string) {
	target := h.repoURL(r, rp) + rel
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	switch {
	case p == "" || p == "simple":
		h.redirect(w, r, rp, "simple/")
	case p == "simple/":
		h.rootIndex(w, r, rp)
	case strings.HasPrefix(p, "simple/"):
		rest := strings.TrimPrefix(p, "simple/")
		name := strings.TrimSuffix(rest, "/")
		if strings.Contains(name, "/") || !ValidName(name) {
			http.NotFound(w, r)
			return
		}
		norm := Normalize(name)
		if norm != name || !strings.HasSuffix(rest, "/") {
			h.redirect(w, r, rp, "simple/"+url.PathEscape(norm)+"/")
			return
		}
		h.projectPage(w, r, rp, norm)
	case strings.HasPrefix(p, "packages/"):
		h.file(w, r, rp, p)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	if _, ok := parseFilePath(p); !ok {
		http.NotFound(w, r)
		return
	}
	owner, a, err := h.find(r.Context(), rp, p)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	st := h.env.Repos.Store
	segs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	switch {
	case segs[0] == "simple" && len(segs) == 2 && rp.IsProxy():
		a, err := h.env.Repos.GetAsset(ctx, rp, "simple/"+Normalize(segs[1]))
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
			h.env.WriteError(w, r, err)
			return
		}
	case segs[0] == "packages" && len(segs) == 4 && !strings.HasSuffix(p, "/"):
		a, err := h.env.Repos.GetAsset(ctx, rp, p)
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if !strings.HasSuffix(p, metadataSuffix) {
			if m, err := h.env.Repos.GetAsset(ctx, rp, p+metadataSuffix); err == nil {
				_, _ = h.env.Repos.Delete(ctx, m.ID)
			}
		}
	case segs[0] == "packages" && (len(segs) == 2 || len(segs) == 3):
		segs[1] = Normalize(segs[1])
		n, err := st.DeleteAssetsByPrefix(ctx, rp.ID, strings.Join(segs, "/")+"/")
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if n == 0 {
			http.NotFound(w, r)
			return
		}
	default:
		http.Error(w, "only packages/{project}/[{version}/[{filename}]] can be deleted", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isNotFound reports whether err means "absent" (as opposed to a failure).
func isNotFound(err error) bool { return errors.Is(err, repo.ErrNotFound) }
