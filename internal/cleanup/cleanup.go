// Package cleanup applies cleanup policies to repositories.
//
// A policy's criteria select components; all criteria that are set must
// match for a component to be removed:
//
//	publishedOlderThanDays       component created more than N days ago
//	lastDownloadedOlderThanDays  no asset downloaded for N days (components
//	                             never downloaded count from their creation)
//	nameRegex, versionRegex      Go regular expressions (unanchored)
//	prereleaseOnly               only pre-release versions (see version.go)
//	keepLatest                   never remove the N newest versions of each
//	                             component name (by version when every
//	                             version of the name parses, else by date)
//
// untaggedOlderThanDays is evaluated independently by formats implementing
// format.Cleaner (Docker: untagged manifests and blob links no remaining
// manifest references).
//
// Repositories list the policies applied to them in cleanup.policies.
// Removing a component deletes all its assets (metadata derived from them is
// regenerated through format.DeleteHook); blob garbage collection reclaims
// the bytes later. Group repositories hold no content and are skipped. For
// proxy repositories cleanup evicts cached content (metadata documents such
// as packuments or index pages are not components and are never touched).
package cleanup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"time"

	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

type Deps struct {
	Store   *store.Store
	Repos   *repo.Service
	Formats *format.Registry
	Logger  *slog.Logger
}

type Service struct {
	Deps
	// now is overridable in tests.
	now func() time.Time
}

func New(d Deps) *Service { return &Service{Deps: d, now: time.Now} }

// Criteria mirrors the API's CleanupCriteria (stored as JSON).
type Criteria struct {
	PublishedOlderThanDays      *int    `json:"publishedOlderThanDays,omitempty"`
	LastDownloadedOlderThanDays *int    `json:"lastDownloadedOlderThanDays,omitempty"`
	NameRegex                   *string `json:"nameRegex,omitempty"`
	VersionRegex                *string `json:"versionRegex,omitempty"`
	PrereleaseOnly              *bool   `json:"prereleaseOnly,omitempty"`
	KeepLatest                  *int    `json:"keepLatest,omitempty"`
	UntaggedOlderThanDays       *int    `json:"untaggedOlderThanDays,omitempty"`
}

// componentCriteria reports whether any component-level criterion is set.
func (c Criteria) componentCriteria() bool {
	return c.PublishedOlderThanDays != nil || c.LastDownloadedOlderThanDays != nil || c.NameRegex != nil ||
		c.VersionRegex != nil || (c.PrereleaseOnly != nil && *c.PrereleaseOnly) || c.KeepLatest != nil
}

// Policy is a compiled cleanup policy.
type Policy struct {
	Name     string
	Format   string
	Criteria Criteria

	nameRe, versionRe *regexp.Regexp
}

// Compile validates criteria and compiles a policy.
func Compile(name, fmtName string, c Criteria) (*Policy, error) {
	p := &Policy{Name: name, Format: fmtName, Criteria: c}
	positive := func(field string, v *int, min int) error {
		if v != nil && *v < min {
			return fmt.Errorf("%s must be at least %d", field, min)
		}
		return nil
	}
	for _, chk := range []error{
		positive("publishedOlderThanDays", c.PublishedOlderThanDays, 1),
		positive("lastDownloadedOlderThanDays", c.LastDownloadedOlderThanDays, 1),
		positive("keepLatest", c.KeepLatest, 0),
		positive("untaggedOlderThanDays", c.UntaggedOlderThanDays, 1),
	} {
		if chk != nil {
			return nil, chk
		}
	}
	var err error
	if c.NameRegex != nil {
		if p.nameRe, err = regexp.Compile(*c.NameRegex); err != nil {
			return nil, fmt.Errorf("invalid nameRegex: %v", err)
		}
	}
	if c.VersionRegex != nil {
		if p.versionRe, err = regexp.Compile(*c.VersionRegex); err != nil {
			return nil, fmt.Errorf("invalid versionRegex: %v", err)
		}
	}
	if !c.componentCriteria() && c.UntaggedOlderThanDays == nil {
		return nil, errors.New("at least one criterion is required")
	}
	if c.UntaggedOlderThanDays != nil && fmtName != "" && fmtName != "docker" {
		return nil, errors.New("untaggedOlderThanDays only applies to docker repositories")
	}
	return p, nil
}

// CompileStored compiles a stored policy.
func CompileStored(sp *store.CleanupPolicy) (*Policy, error) {
	var c Criteria
	if len(sp.Criteria) > 0 {
		if err := json.Unmarshal(sp.Criteria, &c); err != nil {
			return nil, fmt.Errorf("cleanup policy %s: invalid criteria: %w", sp.Name, err)
		}
	}
	p, err := Compile(sp.Name, sp.Format, c)
	if err != nil {
		return nil, fmt.Errorf("cleanup policy %s: %w", sp.Name, err)
	}
	return p, nil
}

// AppliesTo reports whether the policy may run on rp.
func (p *Policy) AppliesTo(rp *repo.Repository) bool {
	return !rp.IsGroup() && (p.Format == "" || p.Format == rp.Format)
}

// Result summarises a run (or a dry run).
type Result struct {
	DryRun       bool
	Repositories []string
	Components   []*store.Component
	// Assets and Bytes count every asset removed (components' assets plus
	// format-specific candidates such as untagged Docker manifests).
	Assets int64
	Bytes  int64
}

func (r *Result) add(o *Result) {
	r.Repositories = append(r.Repositories, o.Repositories...)
	r.Components = append(r.Components, o.Components...)
	r.Assets += o.Assets
	r.Bytes += o.Bytes
}

// Options control a repository run.
type Options struct {
	DryRun bool
	// Policies to apply; nil means the repository's configured policies.
	Policies []string
}

// RunRepository applies policies to one repository.
func (s *Service) RunRepository(ctx context.Context, rp *repo.Repository, o Options) (*Result, error) {
	names := o.Policies
	if names == nil && rp.Cfg.Cleanup != nil {
		names = rp.Cfg.Cleanup.Policies
	}
	res := &Result{DryRun: o.DryRun, Repositories: []string{}, Components: []*store.Component{}}
	if len(names) == 0 || rp.IsGroup() {
		return res, nil
	}
	var policies []*Policy
	for _, n := range names {
		sp, err := s.Store.GetCleanupPolicy(ctx, n)
		if err != nil {
			return nil, err
		}
		p, err := CompileStored(sp)
		if err != nil {
			return nil, err
		}
		if p.AppliesTo(rp) {
			policies = append(policies, p)
		}
	}
	if len(policies) == 0 {
		return res, nil
	}
	comps, assets, err := s.candidates(ctx, rp, policies)
	if err != nil {
		return nil, err
	}
	for _, c := range comps {
		res.Components = append(res.Components, c.Component)
		res.Assets += c.Assets
		res.Bytes += c.Size
	}
	for _, a := range assets {
		res.Assets++
		res.Bytes += a.Size
	}
	if len(comps) > 0 || len(assets) > 0 {
		res.Repositories = append(res.Repositories, rp.Name)
	}
	if o.DryRun {
		return res, nil
	}
	return res, s.delete(ctx, rp, comps, assets)
}

// candidates evaluates policies on rp: components to remove and extra
// format-specific assets (not belonging to those components).
func (s *Service) candidates(ctx context.Context, rp *repo.Repository, policies []*Policy) ([]*store.CleanupComponent, []*store.Asset, error) {
	var comps []*store.CleanupComponent
	needComponents := false
	for _, p := range policies {
		if p.Criteria.componentCriteria() {
			needComponents = true
		}
	}
	if needComponents {
		all, err := s.Store.ListCleanupComponents(ctx, rp.ID)
		if err != nil {
			return nil, nil, err
		}
		selected := map[string]bool{}
		for _, p := range policies {
			if !p.Criteria.componentCriteria() {
				continue
			}
			for _, c := range p.match(rp.Format, all, s.now()) {
				if !selected[c.ID] {
					selected[c.ID] = true
					comps = append(comps, c)
				}
			}
		}
		// Keep the output stable: the listing order.
		sort.SliceStable(comps, func(i, j int) bool {
			if comps[i].Name != comps[j].Name {
				return comps[i].Name < comps[j].Name
			}
			return comps[i].CreatedAt.Before(comps[j].CreatedAt)
		})
	}

	var assets []*store.Asset
	if h, ok := s.Formats.Get(rp.Format); ok {
		if cl, ok := h.(format.Cleaner); ok {
			seen := map[string]bool{}
			for _, p := range policies {
				if p.Criteria.UntaggedOlderThanDays == nil {
					continue
				}
				as, err := cl.CleanupCandidates(ctx, rp, format.CleanupCriteria{
					UntaggedOlderThan: time.Duration(*p.Criteria.UntaggedOlderThanDays) * 24 * time.Hour,
				})
				if err != nil {
					return nil, nil, err
				}
				for _, a := range as {
					if !seen[a.ID] {
						seen[a.ID] = true
						assets = append(assets, a)
					}
				}
			}
		}
	}
	// Assets belonging to selected components are removed with them.
	if len(comps) > 0 && len(assets) > 0 {
		ids := map[string]bool{}
		for _, c := range comps {
			ids[c.ID] = true
		}
		kept := assets[:0]
		for _, a := range assets {
			if a.ComponentID == nil || !ids[*a.ComponentID] {
				kept = append(kept, a)
			}
		}
		assets = kept
	}
	return comps, assets, nil
}

// match returns the components of all that the policy selects.
func (p *Policy) match(fmtName string, all []*store.CleanupComponent, now time.Time) []*store.CleanupComponent {
	c := p.Criteria
	keep := map[string]bool{}
	if c.KeepLatest != nil {
		for _, id := range newest(fmtName, all, *c.KeepLatest) {
			keep[id] = true
		}
	}
	days := func(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }
	var out []*store.CleanupComponent
	for _, cc := range all {
		if keep[cc.ID] {
			continue
		}
		if c.PublishedOlderThanDays != nil && now.Sub(cc.CreatedAt) < days(*c.PublishedOlderThanDays) {
			continue
		}
		if c.LastDownloadedOlderThanDays != nil {
			last := cc.CreatedAt
			if cc.LastDownloadedAt != nil && cc.LastDownloadedAt.After(last) {
				last = *cc.LastDownloadedAt
			}
			if now.Sub(last) < days(*c.LastDownloadedOlderThanDays) {
				continue
			}
		}
		if p.nameRe != nil && !p.nameRe.MatchString(cc.Name) {
			continue
		}
		if p.versionRe != nil && !p.versionRe.MatchString(cc.Version) {
			continue
		}
		if c.PrereleaseOnly != nil && *c.PrereleaseOnly && !isPrerelease(fmtName, cc.Version) {
			continue
		}
		out = append(out, cc)
	}
	return out
}

// newest returns the IDs of the n newest versions of each component name.
func newest(fmtName string, all []*store.CleanupComponent, n int) []string {
	if n <= 0 {
		return nil
	}
	byName := map[string][]*store.CleanupComponent{}
	for _, c := range all {
		byName[c.Name] = append(byName[c.Name], c)
	}
	var ids []string
	for _, cs := range byName {
		parsed := make([]version, len(cs))
		allParse := true
		for i, c := range cs {
			v, ok := parseVersion(fmtName, c.Version)
			if !ok {
				allParse = false
				break
			}
			parsed[i] = v
		}
		idx := make([]int, len(cs))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool {
			x, y := idx[a], idx[b]
			if allParse {
				if c := compareVersions(parsed[x], parsed[y]); c != 0 {
					return c > 0
				}
			}
			return cs[x].CreatedAt.After(cs[y].CreatedAt)
		})
		for i := 0; i < n && i < len(idx); i++ {
			ids = append(ids, cs[idx[i]].ID)
		}
	}
	return ids
}

// delete removes the components' assets and the extra assets, then lets
// the format regenerate derived metadata.
func (s *Service) delete(ctx context.Context, rp *repo.Repository, comps []*store.CleanupComponent, extra []*store.Asset) error {
	var deleted []*store.Asset
	var firstErr error
	del := func(a *store.Asset) {
		if _, err := s.Repos.Delete(ctx, a.ID); err != nil {
			if !errors.Is(err, repo.ErrNotFound) && firstErr == nil {
				firstErr = err
			}
			return
		}
		deleted = append(deleted, a)
	}
	for _, c := range comps {
		as, err := s.Store.ListComponentAssets(ctx, c.ID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, a := range as {
			del(a)
		}
	}
	for _, a := range extra {
		del(a)
	}
	if err := s.Formats.NotifyDeleted(ctx, rp, deleted); err != nil {
		s.Logger.Error("cleanup: regenerate metadata after delete", "repository", rp.Name, "err", err)
	}
	return firstErr
}

// Preview is a dry run of one policy against one repository (whether or
// not the repository is configured with it).
func (s *Service) Preview(ctx context.Context, policy string, rp *repo.Repository) (*Result, error) {
	return s.RunRepository(ctx, rp, Options{DryRun: true, Policies: []string{policy}})
}

// RunAll applies every repository's configured policies.
func (s *Service) RunAll(ctx context.Context, dryRun bool) (*Result, error) {
	repos, err := s.Store.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	total := &Result{DryRun: dryRun, Repositories: []string{}, Components: []*store.Component{}}
	var firstErr error
	for _, r := range repos {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		rp, err := s.Repos.Get(ctx, r.Name)
		if err != nil {
			s.Logger.Warn("cleanup: load repository", "repository", r.Name, "err", err)
			continue
		}
		if rp.Cfg.Cleanup == nil || len(rp.Cfg.Cleanup.Policies) == 0 {
			continue
		}
		res, err := s.RunRepository(ctx, rp, Options{DryRun: dryRun})
		if err != nil {
			s.Logger.Error("cleanup: repository run failed", "repository", rp.Name, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if res == nil {
			continue
		}
		total.add(res)
		if !dryRun && (len(res.Components) > 0 || res.Assets > 0) {
			s.Logger.Info("cleanup: removed content", "repository", rp.Name,
				"components", len(res.Components), "assets", res.Assets, "bytes", res.Bytes)
			s.audit(ctx, "system", rp.Name, res)
		}
	}
	return total, firstErr
}

// AuditDetails is the audit record of a run.
func AuditDetails(r *Result, policies []string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"components": len(r.Components), "assets": r.Assets, "bytes": r.Bytes, "policies": policies,
	})
	return b
}

func (s *Service) audit(ctx context.Context, actor, target string, r *Result) {
	if err := s.Store.Audit(ctx, store.AuditEvent{Actor: actor, Action: "cleanup.run", Target: target,
		Details: AuditDetails(r, nil)}); err != nil {
		s.Logger.Warn("audit", "err", err)
	}
}

// lockKey serialises scheduled runs across replicas.
const lockKey = "entrepot:cleanup"

// Run applies policies every interval until ctx is cancelled (0 disables).
// Replicas coordinate through a Postgres advisory lock and the time of the
// last scheduled run (recorded as a cleanup.schedule audit event), so the
// schedule holds across restarts and only one replica runs at a time.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	check := min(interval, 10*time.Minute)
	t := time.NewTicker(check)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.scheduled(ctx, interval)
	}
}

func (s *Service) scheduled(ctx context.Context, interval time.Duration) {
	release, ok, err := s.Store.TryAdvisoryLock(ctx, lockKey)
	if err != nil {
		s.Logger.Warn("cleanup: lock", "err", err)
		return
	}
	if !ok {
		return
	}
	defer release()
	last, err := s.Store.LastAuditEventAt(ctx, "cleanup.schedule")
	if err != nil {
		s.Logger.Warn("cleanup: last run", "err", err)
		return
	}
	if last != nil && s.now().Sub(*last) < interval-time.Minute {
		return
	}
	if err := s.Store.Audit(ctx, store.AuditEvent{Actor: "system", Action: "cleanup.schedule"}); err != nil {
		s.Logger.Warn("cleanup: record run", "err", err)
		return
	}
	start := s.now()
	res, err := s.RunAll(ctx, false)
	if err != nil {
		s.Logger.Warn("cleanup: scheduled run finished with errors", "err", err)
	}
	if res != nil {
		s.Logger.Info("cleanup: scheduled run", "repositories", len(res.Repositories), "components", len(res.Components),
			"assets", res.Assets, "bytes", res.Bytes, "duration", s.now().Sub(start).Round(time.Millisecond))
	}
}
