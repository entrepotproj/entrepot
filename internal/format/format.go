// Package format defines the plugin interface implemented by each package
// format (raw, pypi, npm, docker, ...) and the shared environment they use.
package format

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/secrets"
	"github.com/entrepotproj/entrepot/internal/signing"
	"github.com/entrepotproj/entrepot/internal/store"
)

// Env is the set of shared services available to format handlers.
type Env struct {
	Config *config.Config
	Repos  *repo.Service
	Proxy  *proxy.Cache
	Auth   *auth.Authenticator
	Authz  *authz.Authorizer
	URLs   httpx.URLs
	Logger *slog.Logger
	// Secrets seals/opens secret values stored in the database.
	Secrets *secrets.Box
	// Signing manages repository signing keys (Apt/Yum).
	Signing *signing.Service
}

// Handler is implemented by every format.
type Handler interface {
	// Name is the format identifier stored on repositories ("npm").
	Name() string
	// Kinds lists the repository kinds the format supports.
	Kinds() []string
	// ServeHTTP handles a request for /repository/{repo}/{path}. path has no
	// leading slash. Handlers must authorise requests (see Env.Authorize).
	ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, path string)
}

// Validator is optionally implemented to validate repository configuration.
type Validator interface {
	ValidateRepository(kind string, cfg repo.Config) error
}

// Uploader is optionally implemented to support the generic upload API
// (POST /api/v1/repositories/{name}/upload).
type Uploader interface {
	Upload(ctx context.Context, rp *repo.Repository, u *Upload) ([]*store.Asset, error)
}

// Upload is a generic multipart upload.
type Upload struct {
	File     multipart.File
	Header   *multipart.FileHeader
	Fields   map[string]string
	Uploader *auth.Principal
}

// DeleteHook is optionally implemented by formats whose metadata is derived
// from stored assets (Apt Packages, Yum repodata, Helm index.yaml). It is
// called after assets were deleted by the management API or by cleanup
// policies, so the format can regenerate its metadata.
type DeleteHook interface {
	AfterDelete(ctx context.Context, rp *repo.Repository, deleted []*store.Asset) error
}

// CleanupCriteria are the format-specific parts of a cleanup policy.
type CleanupCriteria struct {
	// UntaggedOlderThan (Docker): untagged manifests older than this.
	UntaggedOlderThan time.Duration
}

// Cleaner is optionally implemented by formats that have cleanup
// candidates beyond whole components (e.g. untagged Docker manifests and
// blob links no manifest references any more).
type Cleaner interface {
	CleanupCandidates(ctx context.Context, rp *repo.Repository, c CleanupCriteria) ([]*store.Asset, error)
}

// NotifyDeleted calls the format's DeleteHook, if any.
func (r *Registry) NotifyDeleted(ctx context.Context, rp *repo.Repository, deleted []*store.Asset) error {
	if len(deleted) == 0 {
		return nil
	}
	if h, ok := r.m[rp.Format].(DeleteHook); ok {
		return h.AfterDelete(ctx, rp, deleted)
	}
	return nil
}

// RootMounter is optionally implemented by formats that need routes outside
// /repository/{name}/ (Docker mounts /v2/). Mounted routes are behind the
// authentication middleware but must perform their own authorisation.
type RootMounter interface {
	Mount(r chi.Router)
}

// ClientURLer is optionally implemented when the URL package clients should
// use differs from /repository/{name}/ (Docker uses host/{name}).
type ClientURLer interface {
	ClientURL(baseURL string, rp *repo.Repository) string
}

// Registry holds the enabled formats.
type Registry struct {
	m map[string]Handler
}

func NewRegistry(hs ...Handler) *Registry {
	r := &Registry{m: map[string]Handler{}}
	for _, h := range hs {
		r.m[h.Name()] = h
	}
	return r
}

func (r *Registry) Get(name string) (Handler, bool) {
	h, ok := r.m[name]
	return h, ok
}

func (r *Registry) All() []Handler {
	out := make([]Handler, 0, len(r.m))
	for _, h := range r.m {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Supports reports whether the format supports the repository kind.
func Supports(h Handler, kind string) bool {
	for _, k := range h.Kinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// ClientURL is the URL package clients should be configured with.
func (r *Registry) ClientURL(baseURL string, rp *repo.Repository) string {
	if h, ok := r.m[rp.Format]; ok {
		if cu, ok := h.(ClientURLer); ok {
			return cu.ClientURL(baseURL, rp)
		}
	}
	return baseURL + "/repository/" + rp.Name + "/"
}

// Target converts a repository to an authz target.
func Target(rp *repo.Repository) authz.Target {
	return authz.Target{Name: rp.Name, AnonymousRead: rp.AnonymousRead}
}

// Can checks authorisation without writing a response.
func (e *Env) Can(r *http.Request, rp *repo.Repository, a authz.Action) bool {
	return e.Authz.Can(r.Context(), auth.FromContext(r.Context()), a, Target(rp))
}

// Authorize checks that the request principal may perform action on rp. On
// failure it writes 401 (with a Basic challenge) for anonymous callers or 403
// otherwise, and returns false.
func (e *Env) Authorize(w http.ResponseWriter, r *http.Request, rp *repo.Repository, a authz.Action) bool {
	if e.Can(r, rp, a) {
		return true
	}
	p := auth.FromContext(r.Context())
	if p.IsAnonymous() {
		w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	http.Error(w, fmt.Sprintf("%s is not permitted to %s %s", p.Name, a, rp.Name), http.StatusForbidden)
	return false
}

// Members resolves a group repository's member repositories, skipping
// missing members and members of a different format.
func (e *Env) Members(ctx context.Context, rp *repo.Repository) []*repo.Repository {
	if rp.Cfg.Group == nil {
		return nil
	}
	var out []*repo.Repository
	for _, name := range rp.Cfg.Group.Members {
		m, err := e.Repos.Get(ctx, name)
		if err != nil {
			e.Logger.Warn("group member unavailable", "group", rp.Name, "member", name, "err", err)
			continue
		}
		if m.Format != rp.Format || m.Name == rp.Name {
			continue
		}
		out = append(out, m)
	}
	return out
}

// WriteError maps common errors to HTTP responses for format endpoints.
func (e *Env) WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var ue *proxy.UpstreamError
	var ce ClientError
	switch {
	case errors.As(err, &ce):
		http.Error(w, ce.Msg, http.StatusBadRequest)
	case errors.Is(err, ErrBadPath):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, repo.ErrNotFound), errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, repo.ErrRedeploy):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.As(err, &ue):
		e.Logger.Warn("upstream error", "status", ue.Status, "err", err, "path", r.URL.Path)
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
	case errors.Is(err, context.Canceled):
		// client went away
	default:
		e.Logger.Error("format handler error", "err", err, "path", r.URL.Path)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// Actor returns the name recorded as created_by for uploads.
func Actor(r *http.Request) string {
	return auth.FromContext(r.Context()).Name
}

// LimitedBody wraps the request body with a size limit.
func LimitedBody(w http.ResponseWriter, r *http.Request, max int64) io.Reader {
	return http.MaxBytesReader(w, r.Body, max)
}

// ClientError marks an error caused by invalid client input (HTTP 400).
type ClientError struct{ Msg string }

func (e ClientError) Error() string { return e.Msg }

// BadRequest returns a ClientError.
func BadRequest(f string, args ...any) error { return ClientError{Msg: fmt.Sprintf(f, args...)} }
