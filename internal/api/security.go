package api

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
	"github.com/geoffo-dev/package-repository/internal/auth"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// ServiceAccountPrefix is prepended to service account usernames so they
// can never collide with OIDC usernames in role bindings.
const ServiceAccountPrefix = "sa:"

func userToAPI(u *store.User) apigen.User {
	return apigen.User{
		Id: u.ID, Username: u.Username, Issuer: u.Issuer, Subject: u.Subject, Email: u.Email,
		DisplayName: u.DisplayName, Groups: nonNil(u.Groups), ServiceAccount: u.Issuer == auth.ServiceAccountIssuer,
		CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt,
	}
}

func tokenToAPI(t *store.APIToken) apigen.ApiToken {
	return apigen.ApiToken{
		Id: t.ID, Name: t.Name, Hint: t.Hint, Scopes: nonNil(t.Scopes),
		ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, CreatedAt: t.CreatedAt,
	}
}

// ---- Personal tokens ----

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	if !requireAuth(w, r) {
		return nil, false
	}
	p := principal(r)
	if p.UserID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "not_a_user",
			"only users can own API tokens; use a service account (POST /service-accounts/{name}/tokens)")
		return nil, false
	}
	return p, true
}

func (s *Server) ListTokens(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	ts, err := s.Store.ListAPITokens(r.Context(), p.UserID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.ApiToken, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenToAPI(t))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, userID, owner string) {
	var in apigen.ApiTokenInput
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		s.writeErr(w, errBad("name is required"))
		return
	}
	var scopes []string
	if in.Scopes != nil {
		for _, sc := range *in.Scopes {
			if !authz.ValidAction(string(sc)) {
				s.writeErr(w, errBad("invalid scope "+string(sc)))
				return
			}
			scopes = append(scopes, string(sc))
		}
	}
	// A scoped credential cannot mint a broader one.
	if caller := principal(r); len(caller.Scopes) > 0 {
		if len(scopes) == 0 {
			scopes = caller.Scopes
		}
		for _, sc := range scopes {
			if !slices.Contains(caller.Scopes, sc) {
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "cannot create a token with broader scopes than the current credential")
				return
			}
		}
	}
	tok, hash, hint, err := auth.NewAPIToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	t := &store.APIToken{UserID: userID, Name: in.Name, Hint: hint, Scopes: scopes}
	if in.ExpiresInDays != nil && *in.ExpiresInDays > 0 {
		exp := time.Now().Add(time.Duration(*in.ExpiresInDays) * 24 * time.Hour)
		t.ExpiresAt = &exp
	}
	created, err := s.Store.CreateAPIToken(r.Context(), t, hash)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "token.create", owner, map[string]any{"name": in.Name, "scopes": scopes})
	httpx.WriteJSON(w, http.StatusCreated, apigen.ApiTokenCreated{Token: tokenToAPI(created), Secret: tok})
}

func (s *Server) CreateToken(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	s.createToken(w, r, p.UserID, p.Name)
}

func (s *Server) DeleteToken(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteAPIToken(r.Context(), p.UserID, id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "token.delete", p.Name, map[string]string{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Service accounts ----

func (s *Server) serviceAccount(w http.ResponseWriter, r *http.Request, name string) (*store.User, bool) {
	u, err := s.Store.GetUserByIssuerSubject(r.Context(), auth.ServiceAccountIssuer, strings.TrimPrefix(name, ServiceAccountPrefix))
	if err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	return u, true
}

func (s *Server) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	us, err := s.Store.ListUsersByIssuer(r.Context(), auth.ServiceAccountIssuer)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToAPI(u))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.ServiceAccountInput
	if !decode(w, r, &in) {
		return
	}
	if !nameRE.MatchString(in.Name) {
		s.writeErr(w, errBad("invalid name: use lowercase letters, digits, '.', '_' and '-'"))
		return
	}
	u, err := s.Store.CreateUser(r.Context(), &store.User{
		Issuer: auth.ServiceAccountIssuer, Subject: in.Name, Username: ServiceAccountPrefix + in.Name,
		DisplayName: deref(in.Description),
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "serviceaccount.create", u.Username, nil)
	httpx.WriteJSON(w, http.StatusCreated, userToAPI(u))
}

func (s *Server) GetServiceAccount(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	u, ok := s.serviceAccount(w, r, name)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userToAPI(u))
}

func (s *Server) DeleteServiceAccount(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	u, ok := s.serviceAccount(w, r, name)
	if !ok {
		return
	}
	if err := s.Store.DeleteUser(r.Context(), u.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "serviceaccount.delete", u.Username, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListServiceAccountTokens(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	u, ok := s.serviceAccount(w, r, name)
	if !ok {
		return
	}
	ts, err := s.Store.ListAPITokens(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.ApiToken, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenToAPI(t))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateServiceAccountToken(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	u, ok := s.serviceAccount(w, r, name)
	if !ok {
		return
	}
	s.createToken(w, r, u.ID, u.Username)
}

func (s *Server) DeleteServiceAccountToken(w http.ResponseWriter, r *http.Request, name string, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	u, ok := s.serviceAccount(w, r, name)
	if !ok {
		return
	}
	if err := s.Store.DeleteAPIToken(r.Context(), u.ID, id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "token.delete", u.Username, map[string]string{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	us, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToAPI(u))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---- Roles ----

func roleToAPI(r *store.Role) apigen.Role {
	out := apigen.Role{Name: r.Name, Description: r.Description, Builtin: r.Builtin, Actions: []apigen.Action{}}
	for _, a := range r.Actions {
		out.Actions = append(out.Actions, apigen.Action(a))
	}
	return out
}

func roleActions(in apigen.RoleInput) ([]string, error) {
	if len(in.Actions) == 0 {
		return nil, errBad("at least one action is required")
	}
	var out []string
	for _, a := range in.Actions {
		if !authz.ValidAction(string(a)) {
			return nil, errBad("invalid action " + string(a))
		}
		if !slices.Contains(out, string(a)) {
			out = append(out, string(a))
		}
	}
	return out, nil
}

func (s *Server) ListRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rs, err := s.Store.ListRoles(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.Role, 0, len(rs))
	for _, x := range rs {
		out = append(out, roleToAPI(x))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateRole(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RoleInput
	if !decode(w, r, &in) {
		return
	}
	actions, err := roleActions(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if !nameRE.MatchString(in.Name) {
		s.writeErr(w, errBad("invalid role name"))
		return
	}
	role, err := s.Store.CreateRole(r.Context(), &store.Role{Name: in.Name, Description: deref(in.Description), Actions: actions})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Authz.Invalidate()
	s.audit(r, "role.create", in.Name, map[string]any{"actions": actions})
	httpx.WriteJSON(w, http.StatusCreated, roleToAPI(role))
}

func (s *Server) GetRole(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	role, err := s.Store.GetRole(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, roleToAPI(role))
}

func (s *Server) UpdateRole(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RoleInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name != name {
		s.writeErr(w, errBad("role name cannot be changed"))
		return
	}
	actions, err := roleActions(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	role, err := s.Store.UpdateRole(r.Context(), &store.Role{Name: name, Description: deref(in.Description), Actions: actions})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Authz.Invalidate()
	s.audit(r, "role.update", name, map[string]any{"actions": actions})
	httpx.WriteJSON(w, http.StatusOK, roleToAPI(role))
}

func (s *Server) DeleteRole(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Store.DeleteRole(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Authz.Invalidate()
	s.audit(r, "role.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Role bindings ----

func bindingToAPI(b *store.RoleBinding) apigen.RoleBinding {
	return apigen.RoleBinding{
		Id: b.ID, Role: b.Role, SubjectType: apigen.SubjectType(b.SubjectType), Subject: b.Subject,
		RepositoryPattern: b.RepositoryPattern, CreatedAt: b.CreatedAt,
	}
}

func (s *Server) ListRoleBindings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	bs, err := s.Store.ListRoleBindings(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.RoleBinding, 0, len(bs))
	for _, b := range bs {
		out = append(out, bindingToAPI(b))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateRoleBinding(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RoleBindingInput
	if !decode(w, r, &in) {
		return
	}
	b := &store.RoleBinding{
		Role: in.Role, SubjectType: string(in.SubjectType), Subject: strings.TrimSpace(deref(in.Subject)),
		RepositoryPattern: deref(in.RepositoryPattern),
	}
	if b.RepositoryPattern == "" {
		b.RepositoryPattern = "*"
	}
	switch b.SubjectType {
	case authz.SubjectAuthenticated:
		b.Subject = ""
	case authz.SubjectUser, authz.SubjectGroup:
		if b.Subject == "" {
			s.writeErr(w, errBad("subject is required"))
			return
		}
	case authz.SubjectGitLabPolicy:
		if _, err := s.Store.GetGitLabTrustPolicy(r.Context(), b.Subject); err != nil {
			s.writeErr(w, errBad("unknown GitLab trust policy "+b.Subject))
			return
		}
	default:
		s.writeErr(w, errBad("invalid subjectType"))
		return
	}
	created, err := s.Store.CreateRoleBinding(r.Context(), b)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Authz.Invalidate()
	s.audit(r, "rolebinding.create", created.ID, bindingToAPI(created))
	httpx.WriteJSON(w, http.StatusCreated, bindingToAPI(created))
}

func (s *Server) GetRoleBinding(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	bs, err := s.Store.ListRoleBindings(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	for _, b := range bs {
		if b.ID == id {
			httpx.WriteJSON(w, http.StatusOK, bindingToAPI(b))
			return
		}
	}
	httpx.WriteError(w, http.StatusNotFound, "not_found", "role binding not found")
}

func (s *Server) DeleteRoleBinding(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Store.DeleteRoleBinding(r.Context(), id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Authz.Invalidate()
	s.audit(r, "rolebinding.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- GitLab trust policies ----

func policyToAPI(p *store.GitLabTrustPolicy) apigen.GitLabTrustPolicy {
	return apigen.GitLabTrustPolicy{
		Name: p.Name, Description: p.Description, Gitlab: p.GitLab, Conditions: p.Conditions,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func (s *Server) validatePolicy(in apigen.GitLabTrustPolicyInput) error {
	if !nameRE.MatchString(in.Name) {
		return errBad("invalid policy name")
	}
	if !slices.Contains(s.Auth.GitLabInstances(), in.Gitlab) {
		return errBad("unknown GitLab instance " + in.Gitlab + "; configure it under auth.gitlab")
	}
	if len(in.Conditions) == 0 {
		return errBad("at least one condition is required (e.g. project_path)")
	}
	for k, v := range in.Conditions {
		if strings.TrimSpace(k) == "" || v == "" {
			return errBad("conditions must have non-empty claim names and patterns")
		}
	}
	return nil
}

func (s *Server) ListGitLabTrustPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ps, err := s.Store.ListGitLabTrustPolicies(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.GitLabTrustPolicy, 0, len(ps))
	for _, p := range ps {
		out = append(out, policyToAPI(p))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateGitLabTrustPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.GitLabTrustPolicyInput
	if !decode(w, r, &in) {
		return
	}
	if err := s.validatePolicy(in); err != nil {
		s.writeErr(w, err)
		return
	}
	p, err := s.Store.CreateGitLabTrustPolicy(r.Context(), &store.GitLabTrustPolicy{
		Name: in.Name, Description: deref(in.Description), GitLab: in.Gitlab, Conditions: in.Conditions,
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Auth.InvalidatePolicies()
	s.audit(r, "gitlabpolicy.create", p.Name, policyToAPI(p))
	httpx.WriteJSON(w, http.StatusCreated, policyToAPI(p))
}

func (s *Server) GetGitLabTrustPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	p, err := s.Store.GetGitLabTrustPolicy(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, policyToAPI(p))
}

func (s *Server) UpdateGitLabTrustPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.GitLabTrustPolicyInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name != name {
		s.writeErr(w, errBad("policy name cannot be changed"))
		return
	}
	if err := s.validatePolicy(in); err != nil {
		s.writeErr(w, err)
		return
	}
	p, err := s.Store.UpdateGitLabTrustPolicy(r.Context(), &store.GitLabTrustPolicy{
		Name: name, Description: deref(in.Description), GitLab: in.Gitlab, Conditions: in.Conditions,
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Auth.InvalidatePolicies()
	s.audit(r, "gitlabpolicy.update", name, policyToAPI(p))
	httpx.WriteJSON(w, http.StatusOK, policyToAPI(p))
}

func (s *Server) DeleteGitLabTrustPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Store.DeleteGitLabTrustPolicy(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Auth.InvalidatePolicies()
	s.Authz.Invalidate()
	s.audit(r, "gitlabpolicy.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}
