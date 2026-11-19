package npm

import (
	"context"

	"github.com/entrepotproj/entrepot/internal/repo"
)

// maxGroupDepth bounds group nesting when looking for hosted members.
const maxGroupDepth = 4

// groupMembers returns the members of group rp consulted for package name.
//
// With preferHosted (the default), when a hosted repository of the group —
// directly or through nested groups — has the package, only the group's
// hosted repositories are consulted: proxy members never contribute
// versions or tarballs for a name published internally, which protects
// against dependency confusion (a public package with the same name as an
// internal one is not merged in).
func (h *Handler) groupMembers(ctx context.Context, rp *repo.Repository, name string) []*repo.Repository {
	members := h.env.Members(ctx, rp)
	if !rp.Cfg.Group.PrefersHosted() {
		return members
	}
	hosted := h.hostedDescendants(ctx, rp, 0, map[string]bool{})
	for _, m := range hosted {
		cs, err := h.env.Repos.Store.ListComponentsByName(ctx, m.ID, name)
		if err != nil {
			h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "package", name, "err", err)
			continue
		}
		if len(cs) > 0 {
			return hosted
		}
	}
	return members
}

// hostedDescendants lists the hosted repositories of a group in member
// order, flattening nested groups.
func (h *Handler) hostedDescendants(ctx context.Context, rp *repo.Repository, depth int, seen map[string]bool) []*repo.Repository {
	if depth >= maxGroupDepth || seen[rp.ID] {
		return nil
	}
	seen[rp.ID] = true
	var out []*repo.Repository
	for _, m := range h.env.Members(ctx, rp) {
		switch m.Kind {
		case repo.KindHosted:
			if !seen[m.ID] {
				seen[m.ID] = true
				out = append(out, m)
			}
		case repo.KindGroup:
			out = append(out, h.hostedDescendants(ctx, m, depth+1, seen)...)
		}
	}
	return out
}
