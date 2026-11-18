// Package api implements the /api/v1 management API defined in
// api/openapi.yaml (see the generated apigen.ServerInterface).
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
	"github.com/geoffo-dev/package-repository/internal/auth"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// Version is set at build time via -ldflags.
var Version = "dev"

type Server struct {
	Config  *config.Config
	Store   *store.Store
	Repos   *repo.Service
	Blobs   *storage.Registry
	Auth    *auth.Authenticator
	Authz   *authz.Authorizer
	Formats *format.Registry
	URLs    httpx.URLs
	Logger  *slog.Logger
}

var _ apigen.ServerInterface = (*Server)(nil)

// Handler returns the HTTP handler for the API. Mount it at /api/v1.
func (s *Server) Handler() http.Handler {
	return apigen.HandlerWithOptions(s, apigen.ChiServerOptions{
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		},
	})
}

func principal(r *http.Request) *auth.Principal { return auth.FromContext(r.Context()) }

// requireAuth writes 401 for anonymous callers.
func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if principal(r).IsAnonymous() {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return false
	}
	return true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !requireAuth(w, r) {
		return false
	}
	if !s.Authz.IsAdmin(r.Context(), principal(r)) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "administrator access required")
		return false
	}
	return true
}

// requireRepo loads a repository and checks the caller may perform action.
// Repositories the caller cannot read are reported as not found.
func (s *Server) requireRepo(w http.ResponseWriter, r *http.Request, name string, action authz.Action) (*repo.Repository, bool) {
	rp, err := s.Repos.Get(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	p := principal(r)
	t := format.Target(rp)
	if !s.Authz.Can(r.Context(), p, authz.Read, t) && !s.Authz.Can(r.Context(), p, action, t) {
		if p.IsAnonymous() {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		} else {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "repository "+name+" not found")
		}
		return nil, false
	}
	if !s.Authz.Can(r.Context(), p, action, t) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "not permitted to "+string(action)+" "+name)
		return nil, false
	}
	return rp, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

type badRequest struct{ msg string }

func (e badRequest) Error() string { return e.msg }

func errBad(msg string) error { return badRequest{msg} }

func (s *Server) writeErr(w http.ResponseWriter, err error) {
	var br badRequest
	var ce format.ClientError
	switch {
	case errors.As(err, &br):
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", br.msg)
	case errors.As(err, &ce):
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", ce.Msg)
	case errors.Is(err, store.ErrNotFound), errors.Is(err, repo.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, store.ErrConflict), errors.Is(err, repo.ErrRedeploy):
		httpx.WriteError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrInUse):
		httpx.WriteError(w, http.StatusConflict, "in_use", err.Error())
	case errors.Is(err, store.ErrInvalid), errors.Is(err, format.ErrBadPath), errors.Is(err, storage.ErrDigestMismatch):
		httpx.WriteError(w, http.StatusBadRequest, "invalid", err.Error())
	default:
		s.Logger.Error("api error", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// audit records an audit event (best effort).
func (s *Server) audit(r *http.Request, action, target string, details any) {
	raw, _ := json.Marshal(details)
	if details == nil {
		raw = nil
	}
	if err := s.Store.Audit(r.Context(), store.AuditEvent{
		Actor: principal(r).Name, Action: action, Target: target, Details: raw, RemoteIP: httpx.RemoteIP(r),
	}); err != nil {
		s.Logger.Warn("audit", "err", err)
	}
}

func (s *Server) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := apigen.SystemInfo{
		Version:         Version,
		BaseUrl:         s.URLs.BaseURL(r),
		AnonymousAccess: s.Config.Auth.AnonymousAccess,
		GitlabInstances: s.Auth.GitLabInstances(),
		Formats:         []apigen.FormatInfo{},
	}
	if info.GitlabInstances == nil {
		info.GitlabInstances = []string{}
	}
	info.Oidc.Enabled = s.Config.Auth.OIDC.Enabled
	info.Oidc.DisplayName = s.Config.Auth.OIDC.DisplayName
	for _, h := range s.Formats.All() {
		fi := apigen.FormatInfo{Name: h.Name()}
		for _, k := range h.Kinds() {
			fi.Kinds = append(fi.Kinds, apigen.RepositoryKind(k))
		}
		info.Formats = append(info.Formats, fi)
	}
	httpx.WriteJSON(w, http.StatusOK, info)
}

func (s *Server) GetMe(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	me := apigen.Me{
		Kind:     apigen.MeKind(p.Kind),
		Name:     p.Name,
		Groups:   nonNil(p.Groups),
		Policies: nonNil(p.Policies),
		Scopes:   nonNil(p.Scopes),
		Admin:    s.Authz.IsAdmin(r.Context(), p),
	}
	if p.UserID != "" {
		me.UserId = &p.UserID
	}
	if p.Email != "" {
		me.Email = &p.Email
	}
	if len(p.Claims) > 0 {
		me.Claims = &p.Claims
	}
	httpx.WriteJSON(w, http.StatusOK, me)
}

func (s *Server) RunGC(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	n, err := s.Repos.GC(r.Context(), 0)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "maintenance.gc", "", map[string]int{"removed": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"removed": n})
}

func (s *Server) ListAuditEvents(w http.ResponseWriter, r *http.Request, params apigen.ListAuditEventsParams) {
	if !s.requireAdmin(w, r) {
		return
	}
	var before int64
	if params.Before != nil {
		before = *params.Before
	}
	evs, err := s.Store.ListAuditEvents(r.Context(), before, deref(params.Limit))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.AuditEvent, 0, len(evs))
	for _, e := range evs {
		ae := apigen.AuditEvent{Id: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, Target: e.Target, RemoteIp: e.RemoteIP}
		_ = json.Unmarshal(e.Details, &ae.Details)
		if ae.Details == nil {
			ae.Details = map[string]any{}
		}
		out = append(out, ae)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func ptr[T any](v T) *T { return &v }
