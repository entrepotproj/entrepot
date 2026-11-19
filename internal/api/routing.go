package api

import (
	"net/http"
	"regexp"

	"github.com/entrepotproj/entrepot/internal/api/apigen"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/routing"
	"github.com/entrepotproj/entrepot/internal/store"
)

// configNameRe is the name pattern of scanners, cleanup policies and
// routing rules (mirrors the database CHECK constraints).
var configNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (s *Server) routingRuleToAPI(r *http.Request, rr *store.RoutingRule) apigen.RoutingRule {
	out := apigen.RoutingRule{
		Name: rr.Name, Description: rr.Description, Mode: apigen.RoutingRuleMode(rr.Mode),
		Matchers: nonNil(rr.Matchers), CreatedAt: rr.CreatedAt, UpdatedAt: rr.UpdatedAt,
	}
	if users, err := s.Store.RepositoriesUsingRoutingRule(r.Context(), rr.Name); err == nil {
		out.Repositories = &users
	}
	return out
}

func routingRuleInput(in apigen.RoutingRuleInput) (*store.RoutingRule, error) {
	if !configNameRe.MatchString(in.Name) {
		return nil, errBad("name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}
	if _, err := routing.Compile(in.Name, string(in.Mode), in.Matchers); err != nil {
		return nil, errBad(err.Error())
	}
	return &store.RoutingRule{Name: in.Name, Description: deref(in.Description), Mode: string(in.Mode), Matchers: in.Matchers}, nil
}

func (s *Server) ListRoutingRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rules, err := s.Store.ListRoutingRules(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.RoutingRule, 0, len(rules))
	for _, rr := range rules {
		out = append(out, s.routingRuleToAPI(r, rr))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateRoutingRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RoutingRuleInput
	if !decode(w, r, &in) {
		return
	}
	rr, err := routingRuleInput(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	created, err := s.Store.CreateRoutingRule(r.Context(), rr)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Routing.Invalidate(created.Name)
	s.audit(r, "routing_rule.create", created.Name, map[string]any{"mode": created.Mode, "matchers": created.Matchers})
	httpx.WriteJSON(w, http.StatusCreated, s.routingRuleToAPI(r, created))
}

func (s *Server) GetRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	rr, err := s.Store.GetRoutingRule(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.routingRuleToAPI(r, rr))
}

func (s *Server) UpdateRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RoutingRuleInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		in.Name = name
	}
	if in.Name != name {
		s.writeErr(w, errBad("routing rules cannot be renamed"))
		return
	}
	rr, err := routingRuleInput(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	updated, err := s.Store.UpdateRoutingRule(r.Context(), rr)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Routing.Invalidate(name)
	s.audit(r, "routing_rule.update", name, map[string]any{"mode": updated.Mode, "matchers": updated.Matchers})
	httpx.WriteJSON(w, http.StatusOK, s.routingRuleToAPI(r, updated))
}

// DeleteRoutingRule fails with 409 while proxy repositories use the rule.
func (s *Server) DeleteRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Store.DeleteRoutingRule(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Routing.Invalidate(name)
	s.audit(r, "routing_rule.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

// TestRoutingRule evaluates the rule against a subject (a package or image
// name, or a path).
func (s *Server) TestRoutingRule(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.TestRoutingRuleJSONBody
	if !decode(w, r, &in) {
		return
	}
	rr, err := s.Store.GetRoutingRule(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	rule, err := routing.Compile(rr.Name, rr.Mode, rr.Matchers)
	if err != nil {
		s.writeErr(w, errBad(err.Error()))
		return
	}
	allowed, matched := rule.Evaluate(in.Path)
	out := apigen.RoutingTestResult{Allowed: allowed}
	if matched != "" {
		out.Matched = &matched
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
