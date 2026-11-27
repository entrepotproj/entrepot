// Package docker implements Docker / OCI registries (OCI Distribution Spec
// v2) for hosted, proxy (pull-through cache) and group repositories.
//
// Docker clients address registries at the host root, so the format mounts
// /v2/ and /v2/token on the root router. The first path segment after /v2/
// is the Entrepot repository; the rest is the image name:
//
//	docker pull entrepot.example.com/docker-hub/library/alpine:3.20
//	            └── host ──────────┘ └ repo ──┘ └ image ─────┘
//
// Endpoints (name = {repo}/{image}):
//
//	GET    /v2/                                  API check (401 + Bearer challenge for anonymous)
//	GET    /v2/token                             Docker token endpoint (basic auth or anonymous)
//	GET    /v2/_catalog                          images the caller can read
//	GET    /v2/{name}/tags/list                  tags (n/last pagination)
//	GET    /v2/{name}/manifests/{ref}            also HEAD; ref is a tag or digest
//	PUT    /v2/{name}/manifests/{ref}            hosted
//	DELETE /v2/{name}/manifests/{ref}            hosted; digest (and its tags) or a single tag
//	GET    /v2/{name}/blobs/{digest}             also HEAD
//	DELETE /v2/{name}/blobs/{digest}             hosted
//	POST   /v2/{name}/blobs/uploads/             start upload; ?digest= monolithic; ?mount=&from= cross-repo mount
//	PATCH  /v2/{name}/blobs/uploads/{uuid}       append a chunk
//	PUT    /v2/{name}/blobs/uploads/{uuid}       complete (?digest=, optional final chunk)
//	GET    /v2/{name}/blobs/uploads/{uuid}       upload status
//	DELETE /v2/{name}/blobs/uploads/{uuid}       cancel
//
// Storage layout inside a repository (image path components can never start
// with "_", so these never collide with nested image names):
//
//	{image}/_blobs/{digest}      layers and config blobs
//	{image}/_manifests/{digest}  manifests (content type = media type)
//	{image}/_tags/{tag}          tag -> same content as the manifest it points
//	                             to; carries the component (name=image, version=tag)
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
)

// Service is the "service" advertised in Bearer challenges and tokens.
const Service = "entrepot"

const (
	// MaxManifest bounds manifest uploads and fetches.
	MaxManifest = 16 << 20
	// MaxBlob bounds a single blob upload (chunk or monolithic).
	MaxBlob = 64 << 30
)

// Media types.
const (
	MediaDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaOCIIndex           = "application/vnd.oci.image.index.v1+json"
	MediaDockerSchema1      = "application/vnd.docker.distribution.manifest.v1+json"
	MediaDockerSchema1JWS   = "application/vnd.docker.distribution.manifest.v1+prettyjws"
)

// manifestAccept is sent upstream for every manifest request.
var manifestAccept = strings.Join([]string{MediaOCIIndex, MediaOCIManifest, MediaDockerManifestList, MediaDockerManifest}, ", ")

type Handler struct {
	env    *format.Env
	tokens *tokenCache
}

func New(env *format.Env) *Handler { return &Handler{env: env, tokens: newTokenCache()} }

func (h *Handler) Name() string    { return "docker" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

// ClientURL is what users put in front of image names: host/{repo}, or the
// repository's own hostname.
func (h *Handler) ClientURL(baseURL string, rp *repo.Repository) string {
	if dh := rp.Cfg.DockerHost(); dh != "" {
		return dh
	}
	host := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		host = u.Host + strings.TrimRight(u.Path, "/")
	}
	return host + "/" + rp.Name
}

// ValidateRepository checks proxy configuration.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind != repo.KindProxy || cfg.Proxy == nil {
		return nil
	}
	u, err := url.Parse(cfg.Proxy.RemoteURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("proxy.remoteUrl must be an http(s) URL of a registry, e.g. https://registry-1.docker.io")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("proxy.remoteUrl must not contain a query or fragment")
	}
	if p := strings.TrimRight(u.Path, "/"); p != "" && p != "/v2" {
		return errors.New("proxy.remoteUrl must be the registry root (e.g. https://ghcr.io), without a path")
	}
	return nil
}

// ServeHTTP handles /repository/{repo}/...: Docker clients use /v2/.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	http.Error(w, fmt.Sprintf("%s is a Docker registry: use %s/IMAGE[:TAG] with a Docker/OCI client",
		rp.Name, h.ClientURL(h.env.URLs.BaseURL(r), rp)), http.StatusNotFound)
}

// Mount registers the registry API at the root router.
func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.env.Auth.Middleware(h.invalidCredentials), auth.CSRFMiddleware, apiVersionHeader)
		r.Get("/v2/token", h.token)
		r.Post("/v2/token", h.token)
		r.Get("/service/token", h.token)
		r.Post("/service/token", h.token)
		r.HandleFunc("/v2", h.serve)
		r.HandleFunc("/v2/", h.serve)
		r.HandleFunc("/v2/*", h.serve)
	})
}

func apiVersionHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		next.ServeHTTP(w, r)
	})
}

// ---- errors ----------------------------------------------------------------

// Error codes from the distribution spec.
const (
	codeBlobUnknown         = "BLOB_UNKNOWN"
	codeBlobUploadInvalid   = "BLOB_UPLOAD_INVALID"
	codeBlobUploadUnknown   = "BLOB_UPLOAD_UNKNOWN"
	codeDigestInvalid       = "DIGEST_INVALID"
	codeManifestBlobUnknown = "MANIFEST_BLOB_UNKNOWN"
	codeManifestInvalid     = "MANIFEST_INVALID"
	codeManifestUnknown     = "MANIFEST_UNKNOWN"
	codeNameInvalid         = "NAME_INVALID"
	codeNameUnknown         = "NAME_UNKNOWN"
	codeSizeInvalid         = "SIZE_INVALID"
	codeUnauthorized        = "UNAUTHORIZED"
	codeDenied              = "DENIED"
	codeUnsupported         = "UNSUPPORTED"
	codeTooManyRequests     = "TOOMANYREQUESTS"
	codeUnknown             = "UNKNOWN"
)

type regError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

func writeErr(w http.ResponseWriter, status int, code, msg string, detail ...any) {
	e := regError{Code: code, Message: msg}
	if len(detail) > 0 {
		e.Detail = detail[0]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []regError{e}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// fail maps internal errors to registry errors. notFoundCode is used for
// repo.ErrNotFound.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error, notFoundCode string) {
	var ce format.ClientError
	var ue *proxy.UpstreamError
	switch {
	case errors.Is(err, errUpstreamUnavailable):
		h.env.Logger.Warn("docker upstream unavailable", "err", err, "path", r.URL.Path)
		writeErr(w, http.StatusBadGateway, codeUnknown, err.Error())
	case errors.Is(err, errUpstreamCorrupt):
		h.env.Logger.Warn("docker upstream content rejected", "err", err, "path", r.URL.Path)
		writeErr(w, http.StatusBadGateway, codeUnknown, err.Error())
	case errors.Is(err, repo.ErrNotFound):
		writeErr(w, http.StatusNotFound, notFoundCode, strings.ToLower(strings.ReplaceAll(notFoundCode, "_", " ")))
	case errors.Is(err, storage.ErrDigestMismatch):
		writeErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error())
	case errors.Is(err, storage.ErrInvalidDigest):
		writeErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error())
	case errors.As(err, &ce):
		writeErr(w, http.StatusBadRequest, codeUnsupported, ce.Msg)
	case errors.As(err, &ue):
		h.env.Logger.Warn("docker upstream error", "err", err, "path", r.URL.Path)
		if ue.Status == http.StatusTooManyRequests {
			writeErr(w, http.StatusTooManyRequests, codeTooManyRequests, "upstream registry rate limit exceeded")
			return
		}
		writeErr(w, http.StatusBadGateway, codeUnknown, err.Error())
	case errors.Is(err, context.Canceled):
	default:
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, codeSizeInvalid, "content too large")
			return
		}
		h.env.Logger.Error("docker handler error", "err", err, "path", r.URL.Path)
		writeErr(w, http.StatusInternalServerError, codeUnknown, "internal error")
	}
}

// ---- names and paths -------------------------------------------------------

var (
	nameComponentRE = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	imageRE         = regexp.MustCompile(`^` + nameComponentRE + `(?:/` + nameComponentRE + `)*$`)
	tagRE           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	uploadIDRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	manifestsRE = regexp.MustCompile(`^(.+)/manifests/([^/]+)$`)
	uploadsRE   = regexp.MustCompile(`^(.+)/blobs/uploads/([^/]*)$`)
	blobsRE     = regexp.MustCompile(`^(.+)/blobs/([^/]+)$`)
	tagsRE      = regexp.MustCompile(`^(.+)/tags/list$`)
	referrersRE = regexp.MustCompile(`^(.+)/referrers/([^/]+)$`)
)

func blobPath(image string, d storage.Digest) string     { return image + "/_blobs/" + d.String() }
func manifestPath(image string, d storage.Digest) string { return image + "/_manifests/" + d.String() }
func tagPath(image, tag string) string                   { return image + "/_tags/" + tag }
func tagPrefix(image string) string                      { return image + "/_tags/" }

// splitName splits "{repo}/{image}" and validates the image name.
func splitName(name string) (repoName, image string, ok bool) {
	repoName, image, found := strings.Cut(name, "/")
	if !found || repoName == "" || !imageRE.MatchString(image) || len(name) > 255 {
		return "", "", false
	}
	return repoName, image, true
}

// request is a parsed registry request.
type request struct {
	name string // full name {repo}/{image}
	// client is the name as the client addressed it: name, or just the
	// image on the repository's own hostname.
	client string
	rp     *repo.Repository
	image  string
}

// base is the client-visible path of the image (for Location and Link).
func (q *request) base() string { return "/v2/" + q.client }

// onHost reports whether the request came through the repository's own
// hostname.
func (q *request) onHost() bool { return q.client != q.name }

// serve routes /v2/... requests.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/v2")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		h.apiCheck(w, r)
		return
	}
	if p == "_catalog" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
			return
		}
		h.catalog(w, r)
		return
	}
	var (
		name, arg string
		route     string
	)
	if m := uploadsRE.FindStringSubmatch(p); m != nil {
		name, arg, route = m[1], m[2], "uploads"
	} else if m := manifestsRE.FindStringSubmatch(p); m != nil {
		name, arg, route = m[1], m[2], "manifests"
	} else if m := blobsRE.FindStringSubmatch(p); m != nil {
		name, arg, route = m[1], m[2], "blobs"
		if arg == "uploads" { // POST /v2/{name}/blobs/uploads without trailing slash
			arg, route = "", "uploads"
		}
	} else if m := tagsRE.FindStringSubmatch(p); m != nil {
		name, route = m[1], "tags"
	} else if m := referrersRE.FindStringSubmatch(p); m != nil {
		name, arg, route = m[1], m[2], "referrers"
	} else {
		writeErr(w, http.StatusNotFound, codeNameUnknown, "unknown registry endpoint")
		return
	}
	var q *request
	if hr := h.hostRepo(r); hr != nil {
		// The repository's own hostname: the whole name is the image.
		httpx.SetRepository(r.Context(), hr.Name)
		if !imageRE.MatchString(name) || len(name) > 255-len(hr.Name)-1 {
			writeErr(w, http.StatusBadRequest, codeNameInvalid, "invalid image name "+name)
			return
		}
		q = &request{name: hr.Name + "/" + name, client: name, rp: hr, image: name}
	} else {
		repoName, image, ok := splitName(name)
		if !ok {
			writeErr(w, http.StatusBadRequest, codeNameInvalid, "invalid repository name "+name+
				" (expected {entrepot-repository}/{image})")
			return
		}
		if q, ok = h.resolve(w, r, name, repoName, image, route, arg); !ok {
			return
		}
	}
	switch route {
	case "manifests":
		h.manifests(w, r, q, arg)
	case "blobs":
		h.blobs(w, r, q, arg)
	case "uploads":
		h.uploads(w, r, q, arg)
	case "tags":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
			return
		}
		if !h.authorize(w, r, q, pull) {
			return
		}
		h.tagsList(w, r, q)
	case "referrers":
		writeErr(w, http.StatusNotFound, codeUnsupported, "the referrers API is not supported; use the tag schema fallback")
	}
}

// resolve looks up the Entrepot repository for a request.
func (h *Handler) resolve(w http.ResponseWriter, r *http.Request, name, repoName, image, route, arg string) (*request, bool) {
	rp, err := h.env.Repos.Get(r.Context(), repoName)
	if err == nil && rp.Format != h.Name() {
		err = repo.ErrNotFound
	}
	if err != nil {
		if !errors.Is(err, repo.ErrNotFound) {
			h.fail(w, r, err, codeNameUnknown)
			return nil, false
		}
		// Do not reveal which repositories exist to anonymous callers.
		if auth.FromContext(r.Context()).IsAnonymous() {
			h.challenge(w, r, name, actionsFor(r.Method, route), "authentication required")
			return nil, false
		}
		writeErr(w, http.StatusNotFound, codeNameUnknown, "repository "+repoName+" does not exist or is not a docker repository")
		return nil, false
	}
	return &request{name: name, client: name, rp: rp, image: image}, true
}

// actionsFor returns the Docker scope actions a request needs (for challenges).
func actionsFor(method, route string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		if route == "uploads" {
			return "pull,push"
		}
		return "pull"
	case http.MethodDelete:
		if route == "uploads" {
			return "pull,push"
		}
		return "delete"
	}
	return "pull,push"
}
