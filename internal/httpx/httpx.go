// Package httpx holds small HTTP helpers shared across handlers.
package httpx

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
)

// URLs derives externally visible URLs.
type URLs struct {
	// Base is the configured base URL; empty means derive per request.
	Base string
	// TrustForwarded honours X-Forwarded-Proto / X-Forwarded-Host.
	TrustForwarded bool
}

// BaseURL returns the externally visible base URL without trailing slash.
func (u URLs) BaseURL(r *http.Request) string {
	if u.Base != "" {
		return u.Base
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if u.TrustForwarded {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.TrimSpace(strings.Split(p, ",")[0])
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return scheme + "://" + host
}

// RequestHost returns the host the client addressed (X-Forwarded-Host when
// trusted, else the Host header), lowercased and without port.
func (u URLs) RequestHost(r *http.Request) string {
	host := r.Host
	if u.TrustForwarded {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

// RequestOrigin returns scheme://host[:port] as the client addressed it,
// ignoring the configured base URL. The scheme comes from TLS or a trusted
// X-Forwarded-Proto, else from the base URL, else http.
func (u URLs) RequestOrigin(r *http.Request) string {
	scheme := "http"
	if strings.HasPrefix(u.Base, "https://") {
		scheme = "https"
	}
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if u.TrustForwarded {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.TrimSpace(strings.Split(p, ",")[0])
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return scheme + "://" + host
}

// BaseHost returns the hostname of the configured base URL ("" when the
// base URL is derived from requests).
func (u URLs) BaseHost() string {
	if u.Base == "" {
		return ""
	}
	rest := u.Base[strings.Index(u.Base, "://")+3:]
	if i := strings.IndexAny(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		rest = h
	}
	return strings.ToLower(strings.Trim(rest, "[]"))
}

// Error is the JSON error body used by the management API.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
	}
}

func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, Error{Code: code, Message: msg})
}

// RemoteIP returns the client IP (the chi RealIP middleware rewrites
// RemoteAddr when forwarded headers are trusted).
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RequestInfo describes the client of the current request.
type RequestInfo struct {
	RemoteIP  string
	UserAgent string
}

type requestInfoKey struct{}

// WithRequestInfo stores client details for recorders deep in the stack.
func WithRequestInfo(r *http.Request) *http.Request {
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	ctx := context.WithValue(r.Context(), requestInfoKey{}, RequestInfo{RemoteIP: RemoteIP(r), UserAgent: ua})
	return r.WithContext(context.WithValue(ctx, repoHintKey{}, &repoHint{}))
}

type repoHintKey struct{}

type repoHint struct {
	mu   sync.Mutex
	name string
}

// SetRepository records which repository the current request addresses, for
// handlers whose paths don't name it (a Docker repository's own hostname).
func SetRepository(ctx context.Context, name string) {
	if h, ok := ctx.Value(repoHintKey{}).(*repoHint); ok {
		h.mu.Lock()
		h.name = name
		h.mu.Unlock()
	}
}

// RepositoryOf returns the repository recorded with SetRepository.
func RepositoryOf(ctx context.Context) string {
	if h, ok := ctx.Value(repoHintKey{}).(*repoHint); ok {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.name
	}
	return ""
}

// RequestInfoFrom returns the client details stored by WithRequestInfo.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return ri
}
