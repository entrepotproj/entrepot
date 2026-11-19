// Package authz implements role-based access control.
//
// A role is a set of actions (read, write, delete, admin). A role binding
// grants a role to a subject on repositories matching a glob pattern.
// Subjects are users (by username), OIDC groups, GitLab trust policies, or
// every authenticated principal. A binding of a role that includes "admin" on
// pattern "*" makes the subject a system administrator.
package authz

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/entrepotproj/entrepot/internal/auth"
	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/match"
	"github.com/entrepotproj/entrepot/internal/store"
)

type Action string

const (
	Read   Action = "read"
	Write  Action = "write"
	Delete Action = "delete"
	Admin  Action = "admin"
)

var AllActions = []Action{Read, Write, Delete, Admin}

func ValidAction(a string) bool { return slices.Contains(AllActions, Action(a)) }

const (
	SubjectUser          = "user"
	SubjectGroup         = "group"
	SubjectGitLabPolicy  = "gitlab_policy"
	SubjectAuthenticated = "authenticated"
)

// Target is the repository being accessed.
type Target struct {
	Name          string
	AnonymousRead bool
}

type Authorizer struct {
	store  *store.Store
	cfg    *config.Config
	logger *slog.Logger

	mu       sync.Mutex
	loaded   time.Time
	bindings []*store.RoleBinding
}

func New(st *store.Store, cfg *config.Config, logger *slog.Logger) *Authorizer {
	return &Authorizer{store: st, cfg: cfg, logger: logger}
}

// Invalidate forces bindings to be reloaded on next check.
func (z *Authorizer) Invalidate() {
	z.mu.Lock()
	z.loaded = time.Time{}
	z.mu.Unlock()
}

func (z *Authorizer) load(ctx context.Context) []*store.RoleBinding {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.bindings != nil && time.Since(z.loaded) < 5*time.Second {
		return z.bindings
	}
	b, err := z.store.ListRoleBindings(ctx)
	if err != nil {
		z.logger.Error("load role bindings", "err", err)
		if z.bindings != nil {
			return z.bindings // keep last known good
		}
		return nil
	}
	z.bindings, z.loaded = b, time.Now()
	return b
}

func subjectMatches(b *store.RoleBinding, p *auth.Principal) bool {
	if p.IsAnonymous() {
		return false
	}
	switch b.SubjectType {
	case SubjectAuthenticated:
		return true
	case SubjectUser:
		return p.Kind == auth.KindUser && (b.Subject == p.Name || b.Subject == p.UserID)
	case SubjectGroup:
		return p.InGroup(b.Subject)
	case SubjectGitLabPolicy:
		return p.Kind == auth.KindGitLab && slices.Contains(p.Policies, b.Subject)
	}
	return false
}

func roleAllows(actions []string, a Action) bool {
	return slices.Contains(actions, string(a)) || slices.Contains(actions, string(Admin))
}

// IsAdmin reports whether p is a system administrator.
func (z *Authorizer) IsAdmin(ctx context.Context, p *auth.Principal) bool {
	if p.IsAnonymous() {
		return false
	}
	if !p.ScopeAllows(string(Admin)) {
		return false
	}
	if p.Superuser {
		return true
	}
	if p.Kind == auth.KindUser {
		if slices.Contains(z.cfg.Auth.AdminUsers, p.Name) {
			return true
		}
		for _, g := range z.cfg.Auth.AdminGroups {
			if p.InGroup(g) {
				return true
			}
		}
	}
	for _, b := range z.load(ctx) {
		if b.RepositoryPattern == "*" && slices.Contains(b.Actions, string(Admin)) && subjectMatches(b, p) {
			return true
		}
	}
	return false
}

// Can reports whether p may perform action on repository t.
func (z *Authorizer) Can(ctx context.Context, p *auth.Principal, action Action, t Target) bool {
	if action == Read && t.AnonymousRead && (z.cfg.Auth.AnonymousAccess || !p.IsAnonymous()) {
		return true
	}
	if p.IsAnonymous() {
		return false
	}
	if !p.ScopeAllows(string(action)) {
		return false
	}
	if z.IsAdmin(ctx, p) {
		return true
	}
	for _, b := range z.load(ctx) {
		if roleAllows(b.Actions, action) && match.Glob(b.RepositoryPattern, t.Name) && subjectMatches(b, p) {
			return true
		}
	}
	return false
}

// Permissions lists the actions p holds on t (for the UI).
func (z *Authorizer) Permissions(ctx context.Context, p *auth.Principal, t Target) []string {
	out := []string{}
	for _, a := range AllActions {
		if z.Can(ctx, p, a, t) {
			out = append(out, string(a))
		}
	}
	return out
}
