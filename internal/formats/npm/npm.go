// Package npm implements npm registries.
//
// URL layout below /repository/{repo}/ (package names may be scoped, as
// "@scope/name" or "@scope%2fname"):
//
//	GET    {package}                          packument (full, or abbreviated for
//	                                          Accept: application/vnd.npm.install-v1+json)
//	GET    {package}/{version|tag}            a single version manifest
//	GET    {package}/-/{file}.tgz             tarball
//	PUT    {package}                          npm publish / deprecate / unpublish a version
//	PUT    {package}/-rev/{rev}               packument update (npm unpublish pkg@ver)
//	DELETE {package}/-rev/{rev}               unpublish the whole package
//	DELETE {package}/-/{file}.tgz[/-rev/{rev}] delete a tarball
//	GET    -/package/{package}/dist-tags      list dist-tags
//	PUT    -/package/{package}/dist-tags/{tag} set a dist-tag (body: "version")
//	DELETE -/package/{package}/dist-tags/{tag} remove a dist-tag
//	GET    -/v1/search?text=&size=&from=      search
//	GET    -/whoami, -/ping                   client helpers
//	PUT    -/user/org.couchdb.user:{name}     npm login (password = Entrepot API token)
//	POST   -/npm/v1/security/...              audit (forwarded to proxy upstreams)
//
// Hosted repositories keep the packument at {package}/package.json and
// tarballs at {package}/-/{file}.tgz. Proxy repositories cache the upstream
// packument verbatim at the same path and rewrite dist.tarball links at serve
// time. Group repositories merge the packuments of their members (first
// member wins for a version or dist-tag) and serve tarballs from the first
// member that has them.
package npm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/auth"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
)

// MaxPublish bounds the size of a publish request (the tarball is base64
// encoded inside the JSON body).
const MaxPublish = 512 << 20

type Handler struct {
	env   *format.Env
	locks sync.Map // repoID + "\x00" + package -> *sync.Mutex
}

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "npm" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

// ValidateRepository checks proxy configuration.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind == repo.KindProxy && cfg.Proxy != nil {
		u, err := url.Parse(cfg.Proxy.RemoteURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return format.BadRequest("proxy.remoteUrl must be an http(s) URL, e.g. https://registry.npmjs.org")
		}
	}
	return nil
}

// lock serialises packument read-modify-write cycles for one package: a
// local mutex (cheap, avoids holding pool connections for queued writers)
// plus a Postgres advisory lock so replicas do not lose concurrent updates.
func (h *Handler) lock(rp *repo.Repository, name string) func() {
	v, _ := h.locks.LoadOrStore(rp.ID+"\x00"+name, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, err := h.env.Repos.Store.AdvisoryLock(ctx, "npm:"+rp.ID+":"+name)
	if err != nil {
		h.env.Logger.Warn("npm: cluster lock unavailable, using process lock only", "package", name, "err", err)
		return mu.Unlock
	}
	return func() {
		release()
		mu.Unlock()
	}
}

var (
	nameRe    = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)
	newNameRe = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9._~-]*/)?[a-z0-9-~][a-z0-9._~-]*$`)
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

func validName(n string) bool { return len(n) <= 214 && n != "-" && nameRe.MatchString(n) }

// unscoped returns the package name without its scope.
func unscoped(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// escapedName is the form used in registry URLs ("@scope%2fname").
func escapedName(name string) string {
	return strings.Replace(url.PathEscape(name), "%2F", "%2f", 1)
}

// splitPackage splits a (still percent-encoded) path into the package name
// and the remaining, unescaped path segments.
func splitPackage(p string) (string, []string, bool) {
	segs := strings.Split(p, "/")
	var raw string
	switch {
	case strings.HasPrefix(segs[0], "@") && strings.Contains(strings.ToLower(segs[0]), "%2f"):
		raw, segs = segs[0], segs[1:]
	case strings.HasPrefix(segs[0], "@"):
		if len(segs) < 2 {
			return "", nil, false
		}
		raw, segs = segs[0]+"/"+segs[1], segs[2:]
	default:
		raw, segs = segs[0], segs[1:]
	}
	name, err := url.PathUnescape(raw)
	if err != nil || !validName(name) {
		return "", nil, false
	}
	rest := make([]string, 0, len(segs))
	for _, s := range segs {
		u, err := url.PathUnescape(s)
		if err != nil {
			return "", nil, false
		}
		rest = append(rest, u)
	}
	if len(rest) > 0 && rest[len(rest)-1] == "" {
		rest = rest[:len(rest)-1]
	}
	for _, s := range rest {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
			return "", nil, false
		}
	}
	return name, rest, true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if !h.env.Authorize(w, r, rp, authz.Read) {
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"db_name": rp.Name, "registry": "entrepot"})
			return
		}
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if p == "-" || strings.HasPrefix(p, "-/") {
		h.special(w, r, rp, strings.TrimPrefix(strings.TrimPrefix(p, "-"), "/"))
		return
	}
	name, rest, ok := splitPackage(p)
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid package name or path")
		return
	}
	switch {
	case len(rest) == 0:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if h.env.Authorize(w, r, rp, authz.Read) {
				h.getPackument(w, r, rp, name)
			}
		case http.MethodPut:
			if h.writable(w, r, rp, authz.Write) {
				h.putPackument(w, r, rp, name, "")
			}
		default:
			methodNotAllowed(w, "GET, HEAD, PUT")
		}
	case len(rest) == 1:
		// {package}/{version|tag}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		if h.env.Authorize(w, r, rp, authz.Read) {
			h.getVersion(w, r, rp, name, rest[0])
		}
	case rest[0] == "-rev" && len(rest) == 2:
		switch r.Method {
		case http.MethodPut:
			if h.writable(w, r, rp, authz.Write) {
				h.putPackument(w, r, rp, name, rest[1])
			}
		case http.MethodDelete:
			if h.deletable(w, r, rp) {
				h.deletePackage(w, r, rp, name, rest[1])
			}
		default:
			methodNotAllowed(w, "PUT, DELETE")
		}
	case rest[0] == "-" && (len(rest) == 2 || (len(rest) == 4 && rest[2] == "-rev")):
		file := rest[1]
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if len(rest) != 2 {
				jsonError(w, http.StatusNotFound, "not found")
				return
			}
			if h.env.Authorize(w, r, rp, authz.Read) {
				h.getTarball(w, r, rp, name, file)
			}
		case http.MethodDelete:
			if h.deletable(w, r, rp) {
				h.deleteTarball(w, r, rp, name, file)
			}
		default:
			methodNotAllowed(w, "GET, HEAD, DELETE")
		}
	default:
		jsonError(w, http.StatusNotFound, "not found")
	}
}

// writable authorises a write to a hosted repository.
func (h *Handler) writable(w http.ResponseWriter, r *http.Request, rp *repo.Repository, a authz.Action) bool {
	if !rp.IsHosted() {
		jsonError(w, http.StatusMethodNotAllowed, "publishing is only supported by hosted repositories")
		return false
	}
	return h.env.Authorize(w, r, rp, a)
}

// deletable authorises a delete (hosted content, or cached proxy content).
func (h *Handler) deletable(w http.ResponseWriter, r *http.Request, rp *repo.Repository) bool {
	if rp.IsGroup() {
		jsonError(w, http.StatusMethodNotAllowed, "group repositories are read-only")
		return false
	}
	return h.env.Authorize(w, r, rp, authz.Delete)
}

func (h *Handler) special(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	segs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	switch {
	case p == "ping":
		if h.env.Authorize(w, r, rp, authz.Read) {
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	case p == "whoami":
		pr := auth.FromContext(r.Context())
		if pr.IsAnonymous() {
			w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
			jsonError(w, http.StatusUnauthorized, "not logged in: configure an Entrepot API token as _authToken in .npmrc")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": pr.Name})
	case len(segs) == 3 && segs[0] == "user" && segs[1] == "token" && r.Method == http.MethodDelete:
		// npm logout: tokens are managed in Entrepot, nothing to revoke here.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case len(segs) >= 2 && segs[0] == "user" && strings.HasPrefix(segs[1], "org.couchdb.user:"):
		h.login(w, r, rp, segs)
	case p == "v1/search":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		if h.env.Authorize(w, r, rp, authz.Read) {
			h.search(w, r, rp)
		}
	case segs[0] == "package" && len(segs) >= 3:
		h.distTags(w, r, rp, strings.TrimPrefix(p, "package/"))
	case segs[0] == "npm" && len(segs) >= 3 && segs[1] == "v1" && segs[2] == "security":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		if h.env.Authorize(w, r, rp, authz.Read) {
			h.audit(w, r, rp, p)
		}
	default:
		jsonError(w, http.StatusNotFound, "not found")
	}
}

// login answers `npm login` (legacy/couch flow). Entrepot has no npm user
// database: the password must be an Entrepot API token, which is handed back
// to npm as the session token.
func (h *Handler) login(w http.ResponseWriter, r *http.Request, rp *repo.Repository, segs []string) {
	user := strings.TrimPrefix(segs[1], "org.couchdb.user:")
	switch r.Method {
	case http.MethodGet:
		// Lookup after a 409; we never return 409, so there is nothing to show.
		jsonError(w, http.StatusNotFound, "no such user")
		return
	case http.MethodPut:
	default:
		methodNotAllowed(w, "PUT")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	hint := "Entrepot does not manage npm users. Use an Entrepot API token as the password, or set " +
		"//<host>/repository/" + rp.Name + "/:_authToken=<token> in .npmrc"
	if body.Password == "" {
		jsonError(w, http.StatusUnauthorized, hint)
		return
	}
	p, err := h.env.Auth.ResolveToken(r.Context(), body.Password)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			h.env.Logger.Warn("npm login token check failed", "err", err)
		}
		jsonError(w, http.StatusUnauthorized, hint)
		return
	}
	if user == "" {
		user = body.Name
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "id": "org.couchdb.user:" + user, "rev": "1-0", "token": body.Password, "username": p.Name,
	})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps errors to npm style JSON error responses.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ue *proxy.UpstreamError
	var ce format.ClientError
	switch {
	case errors.As(err, &ce):
		jsonError(w, http.StatusBadRequest, ce.Msg)
	case errors.Is(err, format.ErrBadPath), errors.Is(err, storage.ErrDigestMismatch):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, repo.ErrNotFound):
		jsonError(w, http.StatusNotFound, "not found")
	case errors.Is(err, repo.ErrRedeploy), errors.Is(err, errVersionExists):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errRevConflict):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.As(err, &ue):
		h.env.Logger.Warn("upstream error", "status", ue.Status, "err", err, "path", r.URL.Path)
		jsonError(w, http.StatusBadGateway, "bad gateway: "+err.Error())
	default:
		h.env.WriteError(w, r, err)
	}
}
