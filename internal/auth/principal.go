// Package auth authenticates requests. Every client (browser, pip, npm,
// docker, Terraform, GitLab CI) goes through the same Authenticator, which
// accepts:
//
//   - UI session cookies (OIDC login),
//   - Entrepot API tokens ("ent_..."), as Bearer or as a Basic-auth password,
//   - OIDC access tokens from the configured issuer (e.g. Keycloak),
//   - GitLab CI/CD id_tokens from trusted GitLab instances, mapped to
//     GitLab trust policies,
//   - short-lived registry tokens minted by /v2/token for Docker clients,
//   - the bootstrap (break-glass) admin token.
package auth

import (
	"context"
	"slices"
)

type Kind string

const (
	KindAnonymous Kind = "anonymous"
	KindUser      Kind = "user"
	KindGitLab    Kind = "gitlab"
	KindBootstrap Kind = "bootstrap"
)

// Principal is the authenticated identity of a request.
type Principal struct {
	Kind Kind `json:"kind"`
	// UserID is set for users (OIDC or service accounts).
	UserID string `json:"userId,omitempty"`
	// Name is a human readable identity used for audit and created_by.
	Name     string   `json:"name"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Policies []string `json:"policies,omitempty"`
	// Scopes restrict the actions this credential may perform. Empty means
	// the credential carries the full rights of its identity.
	Scopes []string `json:"scopes,omitempty"`
	// Bootstrap admin.
	Superuser bool `json:"superuser,omitempty"`
	// Instance is the trusted GitLab instance name (GitLab principals).
	Instance string `json:"instance,omitempty"`
	// Claims holds the verified GitLab id_token claims.
	Claims map[string]any `json:"claims,omitempty"`
	// ViaCookie is true when authenticated by session cookie (CSRF checks apply).
	ViaCookie bool   `json:"-"`
	TokenID   string `json:"-"`
}

var Anonymous = &Principal{Kind: KindAnonymous, Name: "anonymous"}

func (p *Principal) IsAnonymous() bool { return p == nil || p.Kind == KindAnonymous }

func (p *Principal) InGroup(g string) bool { return slices.Contains(p.Groups, g) }

// ScopeAllows reports whether the credential's scopes permit action.
func (p *Principal) ScopeAllows(action string) bool {
	return len(p.Scopes) == 0 || slices.Contains(p.Scopes, action)
}

type ctxKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request principal (Anonymous if unset).
func FromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(ctxKey{}).(*Principal); ok && p != nil {
		return p
	}
	return Anonymous
}
