package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// ErrInvalidCredentials is returned when credentials were presented but are
// not valid. Requests without credentials are anonymous, not an error.
var ErrInvalidCredentials = errors.New("invalid credentials")

const SessionCookie = "entrepot_session"

var httpClient = &http.Client{Timeout: 15 * time.Second}

// ServiceAccountIssuer marks users created as service accounts.
const ServiceAccountIssuer = "entrepot:service-account"

type Authenticator struct {
	cfg    *config.Config
	store  *store.Store
	Keys   *Keys
	OIDC   *OIDC
	gitlab map[string]*gitlabIssuer // by issuer URL
	logger *slog.Logger

	policies *policyCache
	bearer   *ttlCache
}

func NewAuthenticator(cfg *config.Config, st *store.Store, logger *slog.Logger) (*Authenticator, error) {
	keys, err := DeriveKeys(cfg.Auth.SessionSecret)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		cfg:      cfg,
		store:    st,
		Keys:     keys,
		gitlab:   map[string]*gitlabIssuer{},
		logger:   logger,
		policies: &policyCache{store: st},
		bearer:   newTTLCache(10000),
	}
	if cfg.Auth.OIDC.Enabled {
		a.OIDC = newOIDC(cfg.Auth.OIDC)
	}
	for _, g := range cfg.Auth.GitLab {
		iss := strings.TrimRight(g.IssuerURL, "/")
		a.gitlab[iss] = &gitlabIssuer{name: g.Name, audience: cfg.GitLabAudience(g), lp: &lazyProvider{issuer: iss}}
	}
	return a, nil
}

// GitLabInstances returns the names of trusted GitLab instances.
func (a *Authenticator) GitLabInstances() []string {
	var out []string
	for _, g := range a.cfg.Auth.GitLab {
		out = append(out, g.Name)
	}
	return out
}

// InvalidatePolicies forces trust policies to be reloaded.
func (a *Authenticator) InvalidatePolicies() { a.policies.invalidate() }

// Authenticate resolves the request principal. It returns Anonymous when no
// credentials are present and ErrInvalidCredentials when they are invalid.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, cred, _ := strings.Cut(h, " ")
		cred = strings.TrimSpace(cred)
		switch strings.ToLower(scheme) {
		case "bearer":
			return a.ResolveToken(ctx, cred)
		case "basic":
			_, pass, ok := r.BasicAuth()
			if !ok || pass == "" {
				return nil, ErrInvalidCredentials
			}
			return a.ResolveToken(ctx, pass)
		default:
			return nil, ErrInvalidCredentials
		}
	}
	// npm sends tokens as "Authorization: Bearer"; some tools use a header.
	if tok := r.Header.Get("X-Entrepot-Token"); tok != "" {
		return a.ResolveToken(ctx, tok)
	}
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		p, err := a.sessionPrincipal(ctx, c.Value)
		if err != nil {
			// A stale cookie should not break anonymous access.
			a.logger.Debug("invalid session cookie", "err", err)
			return Anonymous, nil
		}
		p.ViaCookie = true
		return p, nil
	}
	return Anonymous, nil
}

// ResolveToken authenticates a raw credential of any supported kind.
func (a *Authenticator) ResolveToken(ctx context.Context, tok string) (*Principal, error) {
	if tok == "" {
		return nil, ErrInvalidCredentials
	}
	if bt := a.cfg.Auth.BootstrapToken; bt != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(bt)) == 1 {
		return &Principal{Kind: KindBootstrap, Name: "bootstrap-admin", Superuser: true}, nil
	}
	if strings.HasPrefix(tok, TokenPrefix) {
		return a.apiTokenPrincipal(ctx, tok)
	}
	iss := peekIssuer(tok)
	if iss == "" {
		return nil, ErrInvalidCredentials
	}
	if iss == registryIssuer {
		p, err := a.Keys.parseRegistryToken(tok)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
		}
		return p, nil
	}
	cacheKey := string(HashToken(tok))
	if p, ok := a.bearer.get(cacheKey); ok {
		return p, nil
	}
	var (
		p   *Principal
		err error
		exp = time.Now().Add(2 * time.Minute)
	)
	switch {
	case a.OIDC != nil && strings.TrimRight(iss, "/") == strings.TrimRight(a.cfg.Auth.OIDC.IssuerURL, "/"):
		p, err = a.oidcBearerPrincipal(ctx, tok)
	case a.gitlab[strings.TrimRight(iss, "/")] != nil:
		p, err = a.gitlabPrincipal(ctx, a.gitlab[strings.TrimRight(iss, "/")], tok)
		// Policies may change; keep GitLab principals cached briefly.
		exp = time.Now().Add(30 * time.Second)
	default:
		return nil, fmt.Errorf("%w: untrusted token issuer %q", ErrInvalidCredentials, iss)
	}
	if err != nil {
		a.logger.Debug("token rejected", "issuer", iss, "err", err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}
	a.bearer.put(cacheKey, p, exp)
	return p, nil
}

func (a *Authenticator) apiTokenPrincipal(ctx context.Context, tok string) (*Principal, error) {
	t, u, err := a.store.LookupAPIToken(ctx, HashToken(tok))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	go a.store.TouchAPIToken(context.WithoutCancel(ctx), t.ID)
	return &Principal{
		Kind:    KindUser,
		UserID:  u.ID,
		Name:    u.Username,
		Email:   u.Email,
		Groups:  u.Groups,
		Scopes:  t.Scopes,
		TokenID: t.ID,
	}, nil
}

func (a *Authenticator) oidcBearerPrincipal(ctx context.Context, tok string) (*Principal, error) {
	idt, err := a.OIDC.VerifyAccessToken(ctx, tok)
	if err != nil {
		return nil, err
	}
	id, err := a.OIDC.identity(idt)
	if err != nil {
		return nil, err
	}
	u, err := a.store.UpsertUser(ctx, &store.User{
		Issuer: id.Issuer, Subject: id.Subject, Username: id.Username,
		Email: id.Email, DisplayName: id.DisplayName, Groups: id.Groups,
	}, false)
	if err != nil {
		return nil, err
	}
	return userPrincipal(u), nil
}

func userPrincipal(u *store.User) *Principal {
	return &Principal{Kind: KindUser, UserID: u.ID, Name: u.Username, Email: u.Email, Groups: u.Groups}
}

func (a *Authenticator) sessionPrincipal(ctx context.Context, cookie string) (*Principal, error) {
	var s Session
	if err := a.Keys.Open(cookie, &s); err != nil {
		return nil, err
	}
	if time.Now().After(s.Expires) {
		return nil, errors.New("session expired")
	}
	if s.Token != "" {
		return a.ResolveToken(ctx, s.Token)
	}
	if s.UserID == "" {
		return nil, errors.New("empty session")
	}
	u, err := a.store.GetUser(ctx, s.UserID)
	if err != nil {
		return nil, err
	}
	return userPrincipal(u), nil
}

// ttlCache is a small bounded cache of verified bearer tokens.
type ttlCache struct {
	mu  sync.Mutex
	max int
	m   map[string]ttlEntry
}

type ttlEntry struct {
	p   *Principal
	exp time.Time
}

func newTTLCache(max int) *ttlCache { return &ttlCache{max: max, m: map[string]ttlEntry{}} }

func (c *ttlCache) get(k string) (*Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || time.Now().After(e.exp) {
		delete(c.m, k)
		return nil, false
	}
	return e.p, true
}

func (c *ttlCache) put(k string, p *Principal, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		now := time.Now()
		for k, e := range c.m {
			if now.After(e.exp) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max {
			c.m = map[string]ttlEntry{}
		}
	}
	c.m[k] = ttlEntry{p: p, exp: exp}
}
