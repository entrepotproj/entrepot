package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/geoffo-dev/package-repository/internal/match"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// gitlabIssuer verifies CI/CD id_tokens from one GitLab instance.
//
// In .gitlab-ci.yml:
//
//	id_tokens:
//	  ENTREPOT_TOKEN:
//	    aud: https://entrepot.example.com
//
// The job then authenticates with `Authorization: Bearer $ENTREPOT_TOKEN`
// (or as the password with any username for pip/npm/docker).
type gitlabIssuer struct {
	name     string
	audience string
	lp       *lazyProvider
}

func (g *gitlabIssuer) verify(ctx context.Context, raw string) (map[string]any, error) {
	p, err := g.lp.get(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.Verifier(&oidc.Config{ClientID: g.audience}).Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// policyCache caches trust policies for a few seconds.
type policyCache struct {
	store *store.Store

	mu      sync.Mutex
	loaded  time.Time
	entries []*store.GitLabTrustPolicy
}

func (c *policyCache) list(ctx context.Context) ([]*store.GitLabTrustPolicy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loaded) < 5*time.Second && c.entries != nil {
		return c.entries, nil
	}
	ps, err := c.store.ListGitLabTrustPolicies(ctx)
	if err != nil {
		return nil, err
	}
	c.entries, c.loaded = ps, time.Now()
	return ps, nil
}

func (c *policyCache) invalidate() {
	c.mu.Lock()
	c.loaded = time.Time{}
	c.mu.Unlock()
}

// MatchPolicy reports whether a trust policy's conditions all match the
// id_token claims. Conditions are claim -> glob. A policy with no conditions
// never matches (to avoid accidentally trusting every project).
func MatchPolicy(p *store.GitLabTrustPolicy, claims map[string]any) bool {
	if len(p.Conditions) == 0 {
		return false
	}
	for claim, pattern := range p.Conditions {
		v := claimString(claims, claim)
		if _, present := claims[claim]; !present {
			return false
		}
		if !match.Glob(pattern, v) {
			return false
		}
	}
	return true
}

func (a *Authenticator) gitlabPrincipal(ctx context.Context, g *gitlabIssuer, raw string) (*Principal, error) {
	claims, err := g.verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("gitlab id_token: %w", err)
	}
	policies, err := a.policies.list(ctx)
	if err != nil {
		return nil, err
	}
	var matched []string
	for _, p := range policies {
		if p.GitLab == g.name && MatchPolicy(p, claims) {
			matched = append(matched, p.Name)
		}
	}
	sort.Strings(matched)
	name := "gitlab:" + claimString(claims, "project_path")
	if ref := claimString(claims, "ref"); ref != "" {
		name += "@" + ref
	}
	if job := claimString(claims, "job_id"); job != "" {
		name += "#" + job
	}
	// Keep only well-known, non-sensitive claims for display/audit.
	keep := map[string]any{}
	for _, k := range []string{"sub", "project_path", "namespace_path", "ref", "ref_type", "ref_protected",
		"environment", "pipeline_source", "pipeline_id", "job_id", "user_login"} {
		if v, ok := claims[k]; ok {
			keep[k] = v
		}
	}
	return &Principal{
		Kind:     KindGitLab,
		Name:     strings.TrimSuffix(name, "@"),
		Policies: matched,
		Claims:   keep,
	}, nil
}
