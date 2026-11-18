// Package httpx holds small HTTP helpers shared across handlers.
package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
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
