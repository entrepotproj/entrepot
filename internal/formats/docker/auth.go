package docker

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/repo"
)

// TokenTTL is the lifetime of registry tokens issued by /v2/token.
const TokenTTL = 5 * time.Minute

type action string

const (
	pull action = "pull"
	push action = "push"
	del  action = "delete"
)

func (a action) authz() authz.Action {
	switch a {
	case push:
		return authz.Write
	case del:
		return authz.Delete
	}
	return authz.Read
}

func (h *Handler) realm(r *http.Request) string {
	return h.env.URLs.BaseURL(r) + "/v2/token"
}

// challenge answers 401 with a Docker Bearer challenge. name may be "" (no
// scope).
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, name, actions, msg string) {
	c := fmt.Sprintf(`Bearer realm=%q,service=%q`, h.realm(r), Service)
	if name != "" {
		c += fmt.Sprintf(`,scope="repository:%s:%s"`, name, actions)
	}
	w.Header().Set("WWW-Authenticate", c)
	writeErr(w, http.StatusUnauthorized, codeUnauthorized, msg)
}

// invalidCredentials is the authenticator middleware challenge.
func (h *Handler) invalidCredentials(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/token") && (strings.HasPrefix(r.URL.Path, "/v2/") || strings.HasPrefix(r.URL.Path, "/service/")) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
		writeErr(w, http.StatusUnauthorized, codeUnauthorized, "invalid credentials")
		return
	}
	h.challenge(w, r, "", "", "invalid or expired credentials")
}

// apiCheck implements GET /v2/ (also used by docker login).
func (h *Handler) apiCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
		return
	}
	if auth.FromContext(r.Context()).IsAnonymous() {
		h.challenge(w, r, "", "", "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// authorize checks that the caller may perform a on the request repository.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, q *request, a action) bool {
	return h.authorizeRepo(w, r, q.rp, q.name, a)
}

func (h *Handler) authorizeRepo(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name string, a action) bool {
	if h.env.Can(r, rp, a.authz()) {
		return true
	}
	p := auth.FromContext(r.Context())
	if p.IsAnonymous() {
		scope := "pull"
		switch a {
		case push:
			scope = "pull,push"
		case del:
			scope = "delete"
		}
		h.challenge(w, r, name, scope, "authentication required")
		return false
	}
	writeErr(w, http.StatusForbidden, codeDenied,
		fmt.Sprintf("%s is not permitted to %s %s", p.Name, a.authz(), rp.Name))
	return false
}

// token implements the Docker token endpoint
// (https://distribution.github.io/distribution/spec/auth/token/). Credentials
// were already resolved by the authenticator middleware: basic auth with any
// username and an Entrepot API token / bootstrap token / OIDC access token /
// GitLab CI id_token as password, or anonymous. The OAuth2 password grant
// (POST, form-encoded) is accepted too.
func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			writeErr(w, http.StatusBadRequest, codeUnsupported, "invalid form")
			return
		}
		values = r.Form
		switch values.Get("grant_type") {
		case "password":
			if pw := values.Get("password"); pw != "" {
				pp, err := h.env.Auth.ResolveToken(ctx, pw)
				if err != nil {
					w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
					writeErr(w, http.StatusUnauthorized, codeUnauthorized, "invalid credentials")
					return
				}
				p = pp
			}
		case "refresh_token":
			pp, err := h.env.Auth.ResolveToken(ctx, values.Get("refresh_token"))
			if err != nil {
				writeErr(w, http.StatusUnauthorized, codeUnauthorized, "invalid refresh token")
				return
			}
			p = pp
		}
	}
	service := values.Get("service")
	if service == "" {
		service = Service
	}
	var access []auth.RegistryAccess
	for _, s := range values["scope"] {
		for _, one := range strings.Fields(s) {
			if ra, ok := h.grant(r, p, one); ok {
				access = append(access, ra)
			}
		}
	}
	tok, err := h.env.Auth.Keys.IssueRegistryToken(p, service, access, TokenTTL)
	if err != nil {
		h.fail(w, r, err, codeUnknown)
		return
	}
	resp := map[string]any{
		"token":        tok,
		"access_token": tok,
		"expires_in":   int(TokenTTL.Seconds()),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	}
	if r.Method == http.MethodPost && values.Get("access_type") == "offline" && values.Get("grant_type") == "password" {
		// The registry token doubles as a (short-lived) refresh token.
		resp["refresh_token"] = tok
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// grant computes the subset of a requested scope ("repository:{name}:{actions}")
// the principal holds. Authorization is re-evaluated on every registry
// request, so this is informational only.
func (h *Handler) grant(r *http.Request, p *auth.Principal, scope string) (auth.RegistryAccess, bool) {
	// The name may contain a ":port"-less host-style name, so split from the ends.
	typ, rest, ok := strings.Cut(scope, ":")
	if !ok {
		return auth.RegistryAccess{}, false
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return auth.RegistryAccess{}, false
	}
	name, actions := rest[:i], rest[i+1:]
	ra := auth.RegistryAccess{Type: typ, Name: name, Actions: []string{}}
	if typ == "registry" && name == "catalog" {
		if !p.IsAnonymous() {
			ra.Actions = append(ra.Actions, "*")
		}
		return ra, true
	}
	if typ != "repository" {
		return ra, true
	}
	repoName, _, _ := strings.Cut(name, "/")
	rp, err := h.env.Repos.Get(r.Context(), repoName)
	if err != nil || rp.Format != h.Name() {
		return ra, true
	}
	t := format.Target(rp)
	for _, a := range strings.Split(actions, ",") {
		var act action
		switch a {
		case "pull":
			act = pull
		case "push":
			act = push
		case "delete":
			act = del
		case "*":
			for _, x := range []action{pull, push, del} {
				if h.env.Authz.Can(r.Context(), p, x.authz(), t) {
					ra.Actions = append(ra.Actions, string(x))
				}
			}
			continue
		default:
			continue
		}
		if h.env.Authz.Can(r.Context(), p, act.authz(), t) {
			ra.Actions = append(ra.Actions, a)
		}
	}
	return ra, true
}
