package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/store"
)

const loginStateCookie = "entrepot_login"

type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Return   string    `json:"r"`
	Expires  time.Time `json:"e"`
}

// Handlers serves /auth/* endpoints for the web UI.
type Handlers struct {
	A    *Authenticator
	URLs httpx.URLs
	// OnLogin is called after a successful login (for audit).
	OnLogin func(r *http.Request, p *Principal)
}

func randString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Handlers) secure(r *http.Request) bool {
	return strings.HasPrefix(h.URLs.BaseURL(r), "https://")
}

func (h *Handlers) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// safeReturn only allows same-origin relative paths.
func safeReturn(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

// Login starts the OIDC authorization code flow with PKCE.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if h.A.OIDC == nil {
		httpx.WriteError(w, http.StatusNotFound, "oidc_disabled", "single sign-on is not configured")
		return
	}
	oc, _, err := h.A.OIDC.OAuth2(r.Context(), h.URLs.BaseURL(r)+"/auth/callback")
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "oidc_unavailable", err.Error())
		return
	}
	st := loginState{
		State:    randString(24),
		Nonce:    randString(24),
		Verifier: oauth2.GenerateVerifier(),
		Return:   safeReturn(r.URL.Query().Get("return")),
		Expires:  time.Now().Add(10 * time.Minute),
	}
	sealed, err := h.A.Keys.Seal(st)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	h.setCookie(w, r, loginStateCookie, sealed, 10*time.Minute)
	http.Redirect(w, r, oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

// Callback completes the OIDC flow, records the user and sets the session.
func (h *Handlers) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.A.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		httpx.WriteError(w, http.StatusUnauthorized, e, r.URL.Query().Get("error_description"))
		return
	}
	c, err := r.Cookie(loginStateCookie)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "login_state_missing", "login session expired; please try again")
		return
	}
	var st loginState
	if err := h.A.Keys.Open(c.Value, &st); err != nil || time.Now().After(st.Expires) || st.State != r.URL.Query().Get("state") {
		httpx.WriteError(w, http.StatusBadRequest, "login_state_invalid", "invalid login state; please try again")
		return
	}
	h.setCookie(w, r, loginStateCookie, "", -1)

	oc, _, err := h.A.OIDC.OAuth2(ctx, h.URLs.BaseURL(r)+"/auth/callback")
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "oidc_unavailable", err.Error())
		return
	}
	tok, err := oc.Exchange(oidc.ClientContext(ctx, httpClient), r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "code_exchange_failed", err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "no_id_token", "identity provider returned no id_token")
		return
	}
	idt, err := h.A.OIDC.VerifyIDToken(ctx, rawID)
	if err != nil || idt.Nonce != st.Nonce {
		httpx.WriteError(w, http.StatusUnauthorized, "id_token_invalid", "id_token verification failed")
		return
	}
	id, err := h.A.OIDC.identity(idt)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "claims_invalid", err.Error())
		return
	}
	// Groups are often only in the access token or userinfo (Keycloak puts
	// them in all three when the mapper is configured).
	if len(id.Groups) == 0 {
		if at, err := h.A.OIDC.VerifyAccessToken(ctx, tok.AccessToken); err == nil {
			if aid, err := h.A.OIDC.identity(at); err == nil {
				id.Groups = aid.Groups
			}
		}
	}
	u, err := h.A.store.UpsertUser(ctx, &store.User{
		Issuer: id.Issuer, Subject: id.Subject, Username: id.Username,
		Email: id.Email, DisplayName: id.DisplayName, Groups: id.Groups,
	}, true)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	sess := Session{UserID: u.ID, Expires: time.Now().Add(h.A.cfg.Auth.SessionTTL)}
	if len(rawID) < 2000 {
		sess.IDTokenHint = rawID
	}
	if err := h.startSession(w, r, sess); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if h.OnLogin != nil {
		h.OnLogin(r, userPrincipal(u))
	}
	http.Redirect(w, r, safeReturn(st.Return), http.StatusFound)
}

func (h *Handlers) startSession(w http.ResponseWriter, r *http.Request, s Session) error {
	sealed, err := h.A.Keys.Seal(s)
	if err != nil {
		return err
	}
	h.setCookie(w, r, SessionCookie, sealed, time.Until(s.Expires))
	return nil
}

// TokenLogin creates a UI session from an API token (or bootstrap token).
// Useful when no OIDC provider is configured.
func (h *Handlers) TokenLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil || body.Token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "token is required")
		return
	}
	p, err := h.A.ResolveToken(r.Context(), body.Token)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token is not valid")
		return
	}
	if p.Kind == KindGitLab {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported", "CI job tokens cannot be used to log in")
		return
	}
	ttl := h.A.cfg.Auth.SessionTTL
	if err := h.startSession(w, r, Session{Token: body.Token, Expires: time.Now().Add(ttl)}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if h.OnLogin != nil {
		h.OnLogin(r, p)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Logout clears the session and, when possible, ends the IdP session.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var sess Session
	if c, err := r.Cookie(SessionCookie); err == nil {
		_ = h.A.Keys.Open(c.Value, &sess)
	}
	h.setCookie(w, r, SessionCookie, "", -1)
	if r.Method == http.MethodGet && h.A.OIDC != nil && sess.UserID != "" {
		if u := h.endSessionURL(r.Context(), h.URLs.BaseURL(r)+"/", sess.IDTokenHint); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) endSessionURL(ctx context.Context, postLogout, idTokenHint string) string {
	p, err := h.A.OIDC.lp.get(ctx)
	if err != nil {
		return ""
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.EndSession == "" {
		return ""
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("post_logout_redirect_uri", postLogout)
	q.Set("client_id", h.A.cfg.Auth.OIDC.ClientID)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Middleware authenticates every request and stores the principal in the
// context. Invalid credentials yield 401 (with a format-appropriate
// challenge added by the caller via Challenge).
func (a *Authenticator) Middleware(challenge func(w http.ResponseWriter, r *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := a.Authenticate(r)
			if err != nil {
				if !errors.Is(err, ErrInvalidCredentials) {
					a.logger.Error("authentication error", "err", err)
				}
				challenge(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// CSRFMiddleware requires the X-Entrepot-CSRF header on state-changing
// requests authenticated by session cookie. Browsers cannot set custom
// headers cross-origin without a CORS preflight, which we never allow.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if FromContext(r.Context()).ViaCookie && r.Header.Get("X-Entrepot-CSRF") == "" {
				httpx.WriteError(w, http.StatusForbidden, "csrf", "missing X-Entrepot-CSRF header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
