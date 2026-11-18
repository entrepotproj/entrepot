package api

import (
	"encoding/json"
	"net/http"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/cleanup"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/store"
)

func (s *Server) cleanupPolicyToAPI(r *http.Request, p *store.CleanupPolicy) apigen.CleanupPolicy {
	out := apigen.CleanupPolicy{
		Name: p.Name, Description: p.Description, Format: p.Format,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	_ = json.Unmarshal(p.Criteria, &out.Criteria)
	if users, err := s.Store.RepositoriesUsingCleanupPolicy(r.Context(), p.Name); err == nil {
		out.Repositories = &users
	}
	return out
}

func (s *Server) cleanupPolicyInput(in apigen.CleanupPolicyInput) (*store.CleanupPolicy, error) {
	if !configNameRe.MatchString(in.Name) {
		return nil, errBad("name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}
	fmtName := deref(in.Format)
	if fmtName != "" {
		if _, ok := s.Formats.Get(fmtName); !ok {
			return nil, errBad("unknown format " + fmtName)
		}
	}
	c := cleanup.Criteria{
		PublishedOlderThanDays:      in.Criteria.PublishedOlderThanDays,
		LastDownloadedOlderThanDays: in.Criteria.LastDownloadedOlderThanDays,
		NameRegex:                   in.Criteria.NameRegex,
		VersionRegex:                in.Criteria.VersionRegex,
		PrereleaseOnly:              in.Criteria.PrereleaseOnly,
		KeepLatest:                  in.Criteria.KeepLatest,
		UntaggedOlderThanDays:       in.Criteria.UntaggedOlderThanDays,
	}
	if _, err := cleanup.Compile(in.Name, fmtName, c); err != nil {
		return nil, errBad(err.Error())
	}
	raw, _ := json.Marshal(c)
	return &store.CleanupPolicy{Name: in.Name, Description: deref(in.Description), Format: fmtName, Criteria: raw}, nil
}

func (s *Server) cleanupResultToAPI(res *cleanup.Result) apigen.CleanupRunResult {
	out := apigen.CleanupRunResult{
		DryRun: res.DryRun, Repositories: nonNil(res.Repositories), Components: make([]apigen.Component, 0, len(res.Components)),
		Assets: res.Assets, Bytes: res.Bytes,
	}
	for _, c := range res.Components {
		out.Components = append(out.Components, s.componentToAPI(c))
	}
	return out
}

func (s *Server) ListCleanupPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ps, err := s.Store.ListCleanupPolicies(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.CleanupPolicy, 0, len(ps))
	for _, p := range ps {
		out = append(out, s.cleanupPolicyToAPI(r, p))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateCleanupPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.CleanupPolicyInput
	if !decode(w, r, &in) {
		return
	}
	p, err := s.cleanupPolicyInput(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	created, err := s.Store.CreateCleanupPolicy(r.Context(), p)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "cleanup_policy.create", created.Name, map[string]any{"format": created.Format, "criteria": created.Criteria})
	httpx.WriteJSON(w, http.StatusCreated, s.cleanupPolicyToAPI(r, created))
}

func (s *Server) GetCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	p, err := s.Store.GetCleanupPolicy(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.cleanupPolicyToAPI(r, p))
}

func (s *Server) UpdateCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.CleanupPolicyInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		in.Name = name
	}
	if in.Name != name {
		s.writeErr(w, errBad("cleanup policies cannot be renamed"))
		return
	}
	p, err := s.cleanupPolicyInput(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	updated, err := s.Store.UpdateCleanupPolicy(r.Context(), p)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "cleanup_policy.update", name, map[string]any{"format": updated.Format, "criteria": updated.Criteria})
	httpx.WriteJSON(w, http.StatusOK, s.cleanupPolicyToAPI(r, updated))
}

// DeleteCleanupPolicy fails with 409 while repositories list the policy in
// cleanup.policies (remove it from them first).
func (s *Server) DeleteCleanupPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Store.DeleteCleanupPolicy(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "cleanup_policy.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

// PreviewCleanupPolicy is a dry run of one policy on one repository.
func (s *Server) PreviewCleanupPolicy(w http.ResponseWriter, r *http.Request, name string, params apigen.PreviewCleanupPolicyParams) {
	if !s.requireAdmin(w, r) {
		return
	}
	if params.Repository == "" {
		s.writeErr(w, errBad("repository is required"))
		return
	}
	if _, err := s.Store.GetCleanupPolicy(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	rp, err := s.Repos.Get(r.Context(), params.Repository)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	res, err := s.Cleanup.Preview(r.Context(), name, rp)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.cleanupResultToAPI(res))
}

// RunRepositoryCleanup runs the repository's policies (or ?policy=) now.
// Requires admin rights on the repository.
func (s *Server) RunRepositoryCleanup(w http.ResponseWriter, r *http.Request, name string, params apigen.RunRepositoryCleanupParams) {
	rp, ok := s.requireRepo(w, r, name, authz.Admin)
	if !ok {
		return
	}
	o := cleanup.Options{DryRun: deref(params.DryRun)}
	if p := deref(params.Policy); p != "" {
		if _, err := s.Store.GetCleanupPolicy(r.Context(), p); err != nil {
			s.writeErr(w, err)
			return
		}
		o.Policies = []string{p}
	}
	res, err := s.Cleanup.RunRepository(r.Context(), rp, o)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if !o.DryRun {
		policies := o.Policies
		if policies == nil && rp.Cfg.Cleanup != nil {
			policies = rp.Cfg.Cleanup.Policies
		}
		var details map[string]any
		_ = json.Unmarshal(cleanup.AuditDetails(res, policies), &details)
		s.audit(r, "cleanup.run", rp.Name, details)
	}
	httpx.WriteJSON(w, http.StatusOK, s.cleanupResultToAPI(res))
}
