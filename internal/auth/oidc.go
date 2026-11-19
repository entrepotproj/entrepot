package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/entrepotproj/entrepot/internal/config"
)

// lazyProvider performs OIDC discovery on first use and retries on failure,
// so Entrepot can start before the identity provider is reachable.
type lazyProvider struct {
	issuer string

	mu       sync.Mutex
	provider *oidc.Provider
	lastErr  error
	lastTry  time.Time
}

func (l *lazyProvider) get(ctx context.Context) (*oidc.Provider, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.provider != nil {
		return l.provider, nil
	}
	if l.lastErr != nil && time.Since(l.lastTry) < 10*time.Second {
		return nil, l.lastErr
	}
	l.lastTry = time.Now()
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(oidc.ClientContext(dctx, httpClient), l.issuer)
	if err != nil {
		l.lastErr = fmt.Errorf("oidc discovery for %s: %w", l.issuer, err)
		return nil, l.lastErr
	}
	l.provider, l.lastErr = p, nil
	return p, nil
}

// OIDC wraps the configured single sign-on provider.
type OIDC struct {
	cfg config.OIDC
	lp  *lazyProvider
}

func newOIDC(cfg config.OIDC) *OIDC {
	return &OIDC{cfg: cfg, lp: &lazyProvider{issuer: cfg.IssuerURL}}
}

func (o *OIDC) OAuth2(ctx context.Context, redirectURL string) (*oauth2.Config, *oidc.Provider, error) {
	p, err := o.lp.get(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       o.cfg.Scopes,
	}, p, nil
}

// VerifyIDToken verifies an ID token from the login flow.
func (o *OIDC) VerifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, error) {
	p, err := o.lp.get(ctx)
	if err != nil {
		return nil, err
	}
	return p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(ctx, raw)
}

// VerifyAccessToken verifies a JWT access token presented as a bearer token.
// Keycloak access tokens carry the client in "azp" and often aud="account",
// so we accept the token when azp is our client or aud intersects the
// configured bearer audiences.
func (o *OIDC) VerifyAccessToken(ctx context.Context, raw string) (*oidc.IDToken, error) {
	p, err := o.lp.get(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.Verifier(&oidc.Config{SkipClientIDCheck: true}).Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var c struct {
		AZP string `json:"azp"`
	}
	_ = tok.Claims(&c)
	allowed := o.cfg.BearerAudiences
	if len(allowed) == 0 {
		allowed = []string{o.cfg.ClientID}
	}
	if c.AZP == o.cfg.ClientID {
		return tok, nil
	}
	for _, aud := range tok.Audience {
		if slices.Contains(allowed, aud) {
			return tok, nil
		}
	}
	return nil, errors.New("access token audience not accepted")
}

// Identity is the user information extracted from OIDC claims.
type Identity struct {
	Issuer, Subject, Username, Email, DisplayName string
	Groups                                        []string
}

func (o *OIDC) identity(tok *oidc.IDToken) (*Identity, error) {
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, err
	}
	id := &Identity{Issuer: tok.Issuer, Subject: tok.Subject}
	id.Username = claimString(claims, o.cfg.UsernameClaim)
	if id.Username == "" {
		id.Username = claimString(claims, "preferred_username")
	}
	if id.Username == "" {
		id.Username = claimString(claims, "email")
	}
	if id.Username == "" {
		id.Username = tok.Subject
	}
	id.Email = claimString(claims, "email")
	id.DisplayName = claimString(claims, "name")
	id.Groups = claimStrings(claims, o.cfg.GroupsClaim)
	return id, nil
}

func claimString(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	switch v := claims[name].(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", v), "0"), ".")
	}
	return ""
}

// claimStrings reads a string or string-array claim. Keycloak's group mapper
// emits full paths ("/team/devs"); the leading slash is stripped.
func claimStrings(claims map[string]any, name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimPrefix(s, "/")
		if s != "" {
			out = append(out, s)
		}
	}
	switch v := claims[name].(type) {
	case string:
		for _, s := range strings.Split(v, ",") {
			add(strings.TrimSpace(s))
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				add(s)
			}
		}
	}
	return out
}
