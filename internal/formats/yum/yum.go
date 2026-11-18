// Package yum implements RPM (yum/dnf) repositories.
//
// URL layout below /repository/{repo}/:
//
//	GET    {root}/repodata/repomd.xml[.asc]           repository metadata (+ armored signature)
//	GET    {root}/repodata/{sha256}-{type}.xml.gz     primary, filelists, other
//	GET    {path}/{file}.rpm                          packages
//	GET    public.key                                 signing key (armored)
//	GET    [{dir}/]entrepot.repo                      a .repo file for dnf/yum (baseurl = {dir})
//	PUT    {path}/{file}.rpm                          upload a package (hosted)
//	DELETE {path}/{file}.rpm                          delete a package (and regenerate repodata)
//
// Hosted repositories store packages at the path they are uploaded to and
// generate repodata (createrepo_c compatible primary/filelists/other plus a
// signed repomd.xml) for each repodata root: the directory
// hosted.yum.repodataDepth levels below the repository root (0 = the root
// itself, 2 = e.g. el9/x86_64/). Packages must live at or below a root;
// <location href> is relative to it. The repository's OpenPGP key
// (internal/signing) signs repomd.xml (repo_gpgcheck=1); packages are
// served as uploaded (sign them before uploading for gpgcheck=1).
//
// Proxy repositories cache the remote verbatim (upstream signatures stay
// valid): repomd.xml is revalidated after the metadata TTL, repomd.xml.asc
// follows it, checksum-named repodata files and packages are immutable.
package yum

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
)

// MaxUpload is the largest accepted package (4 GiB).
const MaxUpload = 4 << 30

const rpmType = "application/x-rpm"

type Handler struct{ env *format.Env }

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "yum" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy} }

// ValidateRepository checks the proxy remote URL and repodata depth.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind == repo.KindProxy && cfg.Proxy != nil {
		u, err := url.Parse(cfg.Proxy.RemoteURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return format.BadRequest("proxy.remoteUrl must be an http(s) URL, e.g. https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os")
		}
	}
	if kind == repo.KindHosted && cfg.Hosted != nil && cfg.Hosted.Yum != nil {
		if d := cfg.Hosted.Yum.RepodataDepth; d < 0 || d > 5 {
			return format.BadRequest("hosted.yum.repodataDepth must be between 0 and 5")
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
	case http.MethodPut:
		if !rp.IsHosted() {
			http.Error(w, "uploads are only accepted by hosted repositories", http.StatusMethodNotAllowed)
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Write) {
			return
		}
		h.putUpload(w, r, rp, clean)
	case http.MethodDelete:
		if !h.env.Authorize(w, r, rp, authz.Delete) {
			return
		}
		h.delete(w, r, rp, clean)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func contentType(p string) string {
	base := p[strings.LastIndex(p, "/")+1:]
	switch {
	case strings.HasSuffix(base, ".rpm"):
		return rpmType
	case strings.HasSuffix(base, ".xml"):
		return "application/xml"
	case strings.HasSuffix(base, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(base, ".zst"):
		return "application/zstd"
	case strings.HasSuffix(base, ".xz"):
		return "application/x-xz"
	case strings.HasSuffix(base, ".bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(base, ".asc"):
		return "application/pgp-signature"
	case strings.HasSuffix(base, ".sqlite"):
		return "application/vnd.sqlite3"
	case strings.HasPrefix(base, "RPM-GPG-KEY"), strings.HasSuffix(base, ".key"):
		return "application/pgp-keys"
	case strings.HasSuffix(base, ".repo"), base == ".treeinfo", base == "treeinfo":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// parseRPMFilename splits name-version-release.arch.rpm.
func parseRPMFilename(base string) (name, version, arch string, ok bool) {
	s, found := strings.CutSuffix(base, ".rpm")
	if !found {
		return "", "", "", false
	}
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 {
		return "", "", "", false
	}
	arch, s = s[dot+1:], s[:dot]
	relDash := strings.LastIndexByte(s, '-')
	if relDash <= 0 {
		return "", "", "", false
	}
	verDash := strings.LastIndexByte(s[:relDash], '-')
	if verDash <= 0 {
		return "", "", "", false
	}
	return s[:verDash], s[verDash+1:], arch, true
}
