// Package oidctest provides a minimal OpenID Connect issuer for tests. It
// serves discovery and JWKS, mints arbitrary signed tokens (for GitLab CI
// id_tokens and Keycloak-style access tokens) and implements a non-
// interactive authorization code flow that logs in a preset user.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	URL    string
	Server *httptest.Server
	key    *rsa.PrivateKey

	mu sync.Mutex
	// LoginClaims are put in the id_token issued by the code flow.
	LoginClaims map[string]any
	codes       map[string]codeInfo
}

type codeInfo struct {
	nonce, clientID string
}

const kid = "test-key"

func New(t testing.TB) *Issuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &Issuer{key: key, codes: map[string]codeInfo{}, LoginClaims: map[string]any{
		"sub": "user-1", "preferred_username": "alice", "email": "alice@example.com", "name": "Alice", "groups": []string{"/devs"},
	}}
	mux := http.NewServeMux()
	is.Server = httptest.NewServer(mux)
	is.URL = is.Server.URL
	t.Cleanup(is.Server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                is.URL,
			"authorization_endpoint":                is.URL + "/authorize",
			"token_endpoint":                        is.URL + "/token",
			"jwks_uri":                              is.URL + "/jwks",
			"end_session_endpoint":                  is.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := randString()
		is.mu.Lock()
		is.codes[code] = codeInfo{nonce: q.Get("nonce"), clientID: q.Get("client_id")}
		is.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		rq := u.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		u.RawQuery = rq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		is.mu.Lock()
		ci, ok := is.codes[r.Form.Get("code")]
		delete(is.codes, r.Form.Get("code"))
		claims := map[string]any{}
		for k, v := range is.LoginClaims {
			claims[k] = v
		}
		is.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		clientID := ci.clientID
		if clientID == "" {
			clientID, _, _ = r.BasicAuth()
		}
		idClaims := copyClaims(claims)
		idClaims["aud"] = clientID
		idClaims["nonce"] = ci.nonce
		atClaims := copyClaims(claims)
		atClaims["aud"] = "account"
		atClaims["azp"] = clientID
		writeJSON(w, map[string]any{
			"access_token": is.Mint(t, atClaims, time.Hour),
			"id_token":     is.Mint(t, idClaims, time.Hour),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	return is
}

func copyClaims(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Mint signs claims (iss/iat/exp are filled in unless present).
func (is *Issuer) Mint(t testing.TB, claims map[string]any, ttl time.Duration) string {
	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}
	now := time.Now()
	if _, ok := c["iss"]; !ok {
		c["iss"] = is.URL
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = now.Unix()
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = now.Add(ttl).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(is.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// GitLabJobToken mints a GitLab CI/CD id_token for a project and ref.
func (is *Issuer) GitLabJobToken(t testing.TB, aud, project, ref string, protected bool) string {
	ns := project
	if i := lastSlash(project); i >= 0 {
		ns = project[:i]
	}
	prot := "false"
	if protected {
		prot = "true"
	}
	return is.Mint(t, map[string]any{
		"sub":             "project_path:" + project + ":ref_type:branch:ref:" + ref,
		"aud":             aud,
		"namespace_path":  ns,
		"project_path":    project,
		"ref":             ref,
		"ref_type":        "branch",
		"ref_protected":   prot,
		"pipeline_source": "push",
		"job_id":          "42",
		"user_login":      "ci-user",
	}, 5*time.Minute)
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
