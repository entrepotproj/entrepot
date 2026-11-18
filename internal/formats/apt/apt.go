// Package apt implements Debian/Ubuntu (apt) repositories.
//
// URL layout below /repository/{repo}/:
//
//	GET    dists/{dist}/InRelease | Release | Release.gpg     signed release files
//	GET    dists/{dist}/{component}/binary-{arch}/Packages[.gz] package indexes
//	GET    pool/{component}/{prefix}/{package}/{file}.deb      packages
//	GET    public.key | public.gpg                            signing key (armored / binary keyring)
//	PUT    {anything}.deb?distribution=stable&component=main  upload a package (hosted)
//	POST   /  (multipart: file, distribution, component)      upload a package (hosted, curl -F)
//	DELETE pool/.../{file}.deb                                delete a package (and regenerate indexes)
//
// Hosted repositories store packages at
// pool/{component}/{prefix}/{package}/{package}_{version}_{arch}.deb and
// regenerate Packages, Release, InRelease and Release.gpg on every upload
// and delete, signed with the repository's OpenPGP key (internal/signing).
// Clients configure:
//
//	deb [signed-by=/usr/share/keyrings/entrepot.gpg] {base}/repository/{repo} stable main
//
// The published distributions come from hosted.apt.distributions; when none
// are configured, any distribution/component may be uploaded to (default
// "stable"/"main") and the architectures are derived from the uploads.
// Architecture "all" packages are listed in every binary-{arch} index.
//
// Proxy repositories cache dists/ and pool/ verbatim from the remote (e.g.
// http://archive.ubuntu.com/ubuntu), so the upstream signatures stay valid
// and clients keep using the upstream keyring. Release files are revalidated
// after the metadata TTL; index files are refetched whenever they no longer
// match the hashes listed in the cached (In)Release, and by-hash/ and pool/
// files are immutable.
package apt

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
)

// MaxUpload is the largest accepted package (4 GiB).
const MaxUpload = 4 << 30

const debType = "application/vnd.debian.binary-package"

type Handler struct {
	env    *format.Env
	hashes releaseCache
}

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "apt" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy} }

// ValidateRepository checks the proxy remote URL and the distributions of
// hosted repositories.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind == repo.KindProxy && cfg.Proxy != nil {
		u, err := url.Parse(cfg.Proxy.RemoteURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return format.BadRequest("proxy.remoteUrl must be an http(s) URL, e.g. http://archive.ubuntu.com/ubuntu")
		}
	}
	if kind == repo.KindHosted && cfg.Hosted != nil && cfg.Hosted.Apt != nil {
		seen := map[string]bool{}
		for _, d := range cfg.Hosted.Apt.Distributions {
			if !distRe.MatchString(d.Name) {
				return format.BadRequest("invalid distribution name %q (letters, digits, '.', '_' and '-')", d.Name)
			}
			if seen[d.Name] {
				return format.BadRequest("duplicate distribution %q", d.Name)
			}
			seen[d.Name] = true
			for _, c := range d.Components {
				if !componentRe.MatchString(c) {
					return format.BadRequest("distribution %s: invalid component name %q", d.Name, c)
				}
			}
			for _, a := range d.Architectures {
				if !archRe.MatchString(a) {
					return format.BadRequest("distribution %s: invalid architecture %q", d.Name, a)
				}
			}
			if strings.ContainsAny(d.Origin+d.Label, "\n\r") {
				return format.BadRequest("distribution %s: origin and label must be single-line", d.Name)
			}
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
		if rp.IsProxy() {
			h.proxyGet(w, r, rp, clean)
			return
		}
		h.hostedGet(w, r, rp, clean)
	case http.MethodPut, http.MethodPost:
		if !rp.IsHosted() {
			http.Error(w, "uploads are only accepted by hosted repositories", http.StatusMethodNotAllowed)
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Write) {
			return
		}
		if r.Method == http.MethodPost {
			if clean != "" {
				http.Error(w, "POST uploads go to the repository root (multipart field \"file\")", http.StatusNotFound)
				return
			}
			h.postUpload(w, r, rp)
			return
		}
		h.putUpload(w, r, rp, clean)
	case http.MethodDelete:
		if !h.env.Authorize(w, r, rp, authz.Delete) {
			return
		}
		h.delete(w, r, rp, clean)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// contentType maps apt repository files to media types.
func contentType(p string) string {
	base := p[strings.LastIndex(p, "/")+1:]
	switch {
	case strings.HasSuffix(base, ".deb"), strings.HasSuffix(base, ".udeb"), strings.HasSuffix(base, ".ddeb"):
		return debType
	case strings.HasSuffix(base, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(base, ".xz"):
		return "application/x-xz"
	case strings.HasSuffix(base, ".bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(base, ".zst"):
		return "application/zstd"
	case strings.HasSuffix(base, ".lz4"):
		return "application/x-lz4"
	case base == "Release.gpg", strings.HasSuffix(base, ".gpg"):
		return "application/pgp-signature"
	case base == "InRelease", base == "Release", base == "Packages", base == "Sources",
		strings.HasPrefix(base, "Translation-"), strings.HasPrefix(base, "Contents-"), base == "Index":
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(base, ".dsc"):
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	if rp.IsHosted() && !(strings.HasPrefix(p, "pool/") && strings.HasSuffix(p, ".deb")) {
		http.Error(w, "only packages (pool/.../*.deb) can be deleted; indexes are regenerated automatically", http.StatusBadRequest)
		return
	}
	a, err := h.env.Repos.GetAsset(ctx, rp, p)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	if rp.IsHosted() {
		if err := h.Regenerate(ctx, rp); err != nil {
			h.env.WriteError(w, r, fmt.Errorf("regenerate indexes: %w", err))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
