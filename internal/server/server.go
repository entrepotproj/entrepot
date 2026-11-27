// Package server wires all components into the HTTP server.
package server

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	specpkg "github.com/entrepotproj/entrepot/api"
	"github.com/entrepotproj/entrepot/internal/api"
	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
	"github.com/entrepotproj/entrepot/internal/usage"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "entrepot_http_requests_total",
		Help: "HTTP requests by area, method and status code.",
	}, []string{"area", "method", "code"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "entrepot_http_request_duration_seconds",
		Help:    "HTTP request latency by area.",
		Buckets: prometheus.ExponentialBuckets(0.005, 3, 10),
	}, []string{"area"})
)

type Server struct {
	Env     *format.Env
	Store   *store.Store
	Formats *format.Registry
	API     *api.Server
	UI      fs.FS
	Logger  *slog.Logger
	// Usage counts requests per repository (may be nil).
	Usage *usage.Recorder
}

// repoFromPath extracts the repository name from package-client paths.
func repoFromPath(p string) string {
	var rest string
	switch {
	case strings.HasPrefix(p, "/repository/"):
		rest = strings.TrimPrefix(p, "/repository/")
	case strings.HasPrefix(p, "/api/repository/"):
		rest = strings.TrimPrefix(p, "/api/repository/")
	case strings.HasPrefix(p, "/v2/"):
		rest = strings.TrimPrefix(p, "/v2/")
		if rest == "" || rest == "token" || strings.HasPrefix(rest, "_catalog") {
			return ""
		}
	default:
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	return name
}

// Handler builds the root router.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	if s.Env.URLs.TrustForwarded {
		r.Use(middleware.RealIP)
	}
	r.Use(s.recoverer)
	r.Use(s.logAndMeasure)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck
	r.Get("/readyz", s.ready)
	r.Handle("/metrics", promhttp.Handler())

	basicChallenge := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	}
	authn := s.Env.Auth.Middleware(basicChallenge)

	// OpenAPI spec and Swagger UI.
	r.Get("/api/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(specpkg.Spec) //nolint:errcheck
	})
	r.Get("/api/docs", swaggerUI)
	r.Get("/api", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/api/docs", http.StatusFound) })

	apiHandler := s.API.Handler()
	r.Group(func(r chi.Router) {
		r.Use(authn, auth.CSRFMiddleware)
		r.Mount("/api/v1", apiHandler)
	})
	// Webhook scanners authenticate with per-job tokens (Bearer header or
	// ?token=), which are not principals: these routes skip the authenticator.
	scanJobRoute := func(w http.ResponseWriter, r *http.Request) {
		chi.RouteContext(r.Context()).RoutePath = strings.TrimPrefix(r.URL.Path, "/api/v1")
		apiHandler.ServeHTTP(w, r)
	}
	r.Get("/api/v1/scan-jobs/{id}/artifact", scanJobRoute)
	r.Post("/api/v1/scan-jobs/{id}/result", scanJobRoute)

	// Browser login.
	ah := &auth.Handlers{A: s.Env.Auth, URLs: s.Env.URLs, OnLogin: func(r *http.Request, p *auth.Principal) {
		_ = s.Store.Audit(r.Context(), store.AuditEvent{Actor: p.Name, Action: "login", RemoteIP: httpx.RemoteIP(r)})
	}}
	r.Get("/auth/login", ah.Login)
	r.Get("/auth/callback", ah.Callback)
	r.Get("/auth/logout", ah.Logout)
	r.Post("/auth/logout", ah.Logout)
	r.With(requireCSRFHeader).Post("/auth/token-login", ah.TokenLogin)

	// Format endpoints.
	r.Group(func(r chi.Router) {
		r.Use(authn)
		r.HandleFunc("/repository/{repo}", s.dispatch)
		r.HandleFunc("/repository/{repo}/*", s.dispatch)
	})
	for _, h := range s.Formats.All() {
		if m, ok := h.(format.RootMounter); ok {
			m.Mount(r)
		}
	}

	// Web UI (SPA with history fallback).
	r.NotFound(s.ui)
	return r
}

func requireCSRFHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Entrepot-CSRF") == "" {
			httpx.WriteError(w, http.StatusForbidden, "csrf", "missing X-Entrepot-CSRF header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "repo")
	rest := chi.URLParam(r, "*")
	rp, err := s.Env.Repos.Get(r.Context(), name)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			http.Error(w, "repository "+name+" not found", http.StatusNotFound)
			return
		}
		s.Env.WriteError(w, r, err)
		return
	}
	h, ok := s.Formats.Get(rp.Format)
	if !ok {
		http.Error(w, "format "+rp.Format+" is not enabled", http.StatusNotImplemented)
		return
	}
	// Preserve percent-encoding of the path (e.g. npm scoped packages "@scope%2fname").
	if raw := r.URL.EscapedPath(); raw != "" {
		prefix := "/repository/" + name + "/"
		if strings.HasPrefix(raw, prefix) {
			rest = strings.TrimPrefix(raw, prefix)
		} else if raw == "/repository/"+name {
			rest = ""
		}
	}
	h.ServeHTTP(w, r, rp, rest)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready")) //nolint:errcheck
}

func area(p string) string {
	switch {
	case strings.HasPrefix(p, "/api/"):
		return "api"
	case strings.HasPrefix(p, "/repository/"):
		return "repository"
	case strings.HasPrefix(p, "/v2"):
		return "docker"
	case strings.HasPrefix(p, "/auth/"):
		return "auth"
	case p == "/metrics" || p == "/healthz" || p == "/readyz":
		return "system"
	}
	return "ui"
}

func (s *Server) logAndMeasure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r = httpx.WithRequestInfo(r)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		name := httpx.RepositoryOf(r.Context())
		if name == "" {
			name = repoFromPath(r.URL.Path)
		}
		if name != "" && s.Usage != nil {
			if rp, err := s.Env.Repos.Get(r.Context(), name); err == nil {
				st := ww.Status()
				if st == 0 {
					st = http.StatusOK
				}
				s.Usage.Request(repo.UsageRepo(rp), st)
			}
		}
		a := area(r.URL.Path)
		dur := time.Since(start)
		code := ww.Status()
		if code == 0 {
			code = http.StatusOK
		}
		httpRequests.WithLabelValues(a, r.Method, strconv.Itoa(code)).Inc()
		httpDuration.WithLabelValues(a).Observe(dur.Seconds())
		if a == "system" || (a == "ui" && code < 400) {
			return
		}
		s.Logger.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", code, "bytes", ww.BytesWritten(),
			"duration_ms", dur.Milliseconds(), "remote", httpx.RemoteIP(r),
			"principal", auth.FromContext(r.Context()).Name, "request_id", middleware.GetReqID(r.Context()))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Logger.Error("panic", "value", v, "path", r.URL.Path, "stack", string(debugStack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p != "" {
		if st, err := fs.Stat(s.UI, p); err == nil && !st.IsDir() {
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, s.UI, p)
			return
		}
		// Unknown file-like paths 404; everything else is a client route.
		if path.Ext(p) != "" {
			http.NotFound(w, r)
			return
		}
	}
	if _, err := fs.Stat(s.UI, "index.html"); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!doctype html><title>Entrepot</title><h1>Entrepot</h1>
<p>The web UI has not been built into this binary. Run <code>make ui</code> and rebuild.</p>
<p>The API is available at <a href="/api/docs">/api/docs</a>.</p>`)) //nolint:errcheck
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, s.UI, "index.html")
}

const swaggerVersion = "5.17.14"

func swaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!doctype html>
<html><head><meta charset="utf-8"><title>Entrepot API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@` + swaggerVersion + `/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@` + swaggerVersion + `/swagger-ui-bundle.js" crossorigin></script>
<script>
window.ui = SwaggerUIBundle({
  url: "/api/openapi.yaml",
  dom_id: "#swagger-ui",
  deepLinking: true,
  persistAuthorization: true,
  requestInterceptor: (req) => { req.headers["X-Entrepot-CSRF"] = "1"; return req; },
});
</script></body></html>`)) //nolint:errcheck
}
