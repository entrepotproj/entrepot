package httpx

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestRequestHostAndOrigin(t *testing.T) {
	for _, c := range []struct {
		name          string
		urls          URLs
		host, fwdHost string
		fwdProto      string
		tls           bool
		wantHost      string
		wantOrigin    string
	}{
		{"plain", URLs{}, "Hub.Example.com:8080", "", "", false, "hub.example.com", "http://Hub.Example.com:8080"},
		{"base scheme", URLs{Base: "https://entrepot.example.com"}, "hub.example.com", "", "", false, "hub.example.com", "https://hub.example.com"},
		{"tls", URLs{}, "hub.example.com", "", "", true, "hub.example.com", "https://hub.example.com"},
		{"forwarded, untrusted", URLs{}, "internal:8080", "hub.example.com", "https", false, "internal", "http://internal:8080"},
		{"forwarded, trusted", URLs{TrustForwarded: true}, "internal:8080", "hub.example.com, proxy", "https", false, "hub.example.com", "https://hub.example.com"},
		{"ipv6", URLs{}, "[::1]:5000", "", "", false, "::1", "http://[::1]:5000"},
		{"trailing dot", URLs{}, "hub.example.com.", "", "", false, "hub.example.com", "http://hub.example.com."},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v2/", nil)
			r.Host = c.host
			if c.fwdHost != "" {
				r.Header.Set("X-Forwarded-Host", c.fwdHost)
			}
			if c.fwdProto != "" {
				r.Header.Set("X-Forwarded-Proto", c.fwdProto)
			}
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			if got := c.urls.RequestHost(r); got != c.wantHost {
				t.Errorf("RequestHost = %q, want %q", got, c.wantHost)
			}
			if got := c.urls.RequestOrigin(r); got != c.wantOrigin {
				t.Errorf("RequestOrigin = %q, want %q", got, c.wantOrigin)
			}
		})
	}
	for base, want := range map[string]string{"": "", "https://Entrepot.example.com": "entrepot.example.com",
		"http://127.0.0.1:8080/prefix": "127.0.0.1", "https://[::1]:443": "::1"} {
		if got := (URLs{Base: base}).BaseHost(); got != want {
			t.Errorf("BaseHost(%q) = %q, want %q", base, got, want)
		}
	}
}
