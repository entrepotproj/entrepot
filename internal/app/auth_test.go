package app_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/testutil"
	"github.com/entrepotproj/entrepot/internal/testutil/oidctest"
)

func withIdP(is *oidctest.Issuer) testutil.Option {
	return func(c *config.Config) {
		c.Auth.OIDC = config.OIDC{
			Enabled: true, IssuerURL: is.URL, ClientID: "entrepot", ClientSecret: "secret",
			Scopes: []string{"openid", "profile"}, GroupsClaim: "groups", UsernameClaim: "preferred_username",
			DisplayName: "Keycloak",
		}
		c.Auth.AdminGroups = []string{"platform-admins"}
		c.Auth.GitLab = []config.GitLabSpec{{Name: "gitlab", IssuerURL: is.URL + "/gitlab"}}
	}
}

func TestGitLabTrustPolicies(t *testing.T) {
	idp := oidctest.New(t)
	gl := oidctest.New(t) // a separate issuer acting as GitLab
	inst := testutil.New(t, withIdP(idp), func(c *config.Config) {
		c.Auth.GitLab = []config.GitLabSpec{{Name: "gitlab", IssuerURL: gl.URL}}
	})
	aud := inst.URL
	inst.CreateRepo("releases", "raw", "hosted", map[string]any{"hosted": map[string]any{"allowRedeploy": true}})
	inst.CreateRepo("other", "raw", "hosted", nil)

	inst.JSON("POST", "/gitlab-trust-policies", map[string]any{
		"name": "platform-protected", "gitlab": "gitlab",
		"conditions": map[string]string{"project_path": "platform/**", "ref_protected": "true"},
	}, http.StatusCreated, nil)
	inst.JSON("POST", "/role-bindings", map[string]any{
		"role": "developer", "subjectType": "gitlab_policy", "subject": "platform-protected", "repositoryPattern": "releases",
	}, http.StatusCreated, nil)
	// Unknown instance and empty conditions are rejected.
	inst.JSON("POST", "/gitlab-trust-policies", map[string]any{
		"name": "bad", "gitlab": "nope", "conditions": map[string]string{"project_path": "*"},
	}, http.StatusBadRequest, nil)
	inst.JSON("POST", "/gitlab-trust-policies", map[string]any{
		"name": "bad", "gitlab": "gitlab", "conditions": map[string]string{},
	}, http.StatusBadRequest, nil)

	put := func(tok, repo string) int {
		resp := inst.Do("PUT", "/repository/"+repo+"/app.tgz", tok, strings.NewReader("artifact"))
		testutil.Body(resp)
		return resp.StatusCode
	}
	good := gl.GitLabJobToken(t, aud, "platform/services/api", "main", true)
	if got := put(good, "releases"); got != http.StatusCreated {
		t.Fatalf("trusted job push: %d", got)
	}
	if got := put(good, "other"); got != http.StatusForbidden {
		t.Fatalf("push to unbound repo: %d", got)
	}
	if got := put(gl.GitLabJobToken(t, aud, "platform/services/api", "feature", false), "releases"); got != http.StatusForbidden {
		t.Fatalf("unprotected ref should be denied: %d", got)
	}
	if got := put(gl.GitLabJobToken(t, aud, "evil/platform", "main", true), "releases"); got != http.StatusForbidden {
		t.Fatalf("other project should be denied: %d", got)
	}
	if got := put(gl.GitLabJobToken(t, "https://wrong-audience", "platform/api", "main", true), "releases"); got != http.StatusUnauthorized {
		t.Fatalf("wrong audience should be 401: %d", got)
	}
	expired := gl.Mint(t, map[string]any{"aud": aud, "project_path": "platform/api", "ref_protected": "true",
		"exp": time.Now().Add(-time.Hour).Unix()}, 0)
	if got := put(expired, "releases"); got != http.StatusUnauthorized {
		t.Fatalf("expired token should be 401: %d", got)
	}
	// Tokens from the login IdP are not accepted as GitLab tokens.
	forged := idp.Mint(t, map[string]any{"aud": aud, "project_path": "platform/api", "ref_protected": "true"}, time.Minute)
	if got := put(forged, "releases"); got == http.StatusCreated {
		t.Fatalf("token from a different issuer must not match GitLab policies")
	}
	// Basic auth with the id_token as password (pip/npm/docker style).
	req, _ := http.NewRequest("GET", inst.URL+"/repository/releases/app.tgz", nil)
	req.SetBasicAuth("gitlab-ci-token", good)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := testutil.Expect(t, resp, http.StatusOK); b != "artifact" {
		t.Fatalf("got %q", b)
	}
	// /me reports the matched policies.
	var me map[string]any
	resp = inst.Do("GET", "/api/v1/me", good, nil)
	_ = json.Unmarshal([]byte(testutil.Expect(t, resp, http.StatusOK)), &me)
	if me["kind"] != "gitlab" || !strings.Contains(toJSON(me["policies"]), "platform-protected") {
		t.Fatalf("unexpected /me: %v", me)
	}
	// Deleting the policy revokes access.
	inst.JSON("DELETE", "/gitlab-trust-policies/platform-protected", nil, http.StatusNoContent, nil)
	time.Sleep(50 * time.Millisecond)
	fresh := gl.GitLabJobToken(t, aud, "platform/services/web", "main", true)
	if got := put(fresh, "releases"); got != http.StatusForbidden {
		t.Fatalf("after policy deletion: %d", got)
	}
}

func TestOIDCBearerAndGroups(t *testing.T) {
	idp := oidctest.New(t)
	inst := testutil.New(t, withIdP(idp))
	inst.CreateRepo("libs", "raw", "hosted", nil)
	testutil.Expect(t, inst.Do("PUT", "/repository/libs/a.txt", testutil.BootstrapToken, strings.NewReader("a")), http.StatusCreated)
	inst.JSON("POST", "/role-bindings", map[string]any{
		"role": "viewer", "subjectType": "group", "subject": "devs", "repositoryPattern": "lib*",
	}, http.StatusCreated, nil)

	access := idp.Mint(t, map[string]any{"sub": "u-bob", "preferred_username": "bob", "azp": "entrepot",
		"aud": "account", "groups": []string{"/devs"}}, time.Hour)
	testutil.Expect(t, inst.Do("GET", "/repository/libs/a.txt", access, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("PUT", "/repository/libs/b.txt", access, strings.NewReader("b")), http.StatusForbidden)

	// Token for another client is rejected.
	foreign := idp.Mint(t, map[string]any{"sub": "u-bob", "azp": "other-app", "aud": "other-app"}, time.Hour)
	testutil.Expect(t, inst.Do("GET", "/api/v1/me", foreign, nil), http.StatusUnauthorized)

	// Admin group from configuration.
	admin := idp.Mint(t, map[string]any{"sub": "u-root", "preferred_username": "root", "azp": "entrepot",
		"groups": []string{"platform-admins"}}, time.Hour)
	var me map[string]any
	_ = json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", "/api/v1/me", admin, nil), http.StatusOK)), &me)
	if me["admin"] != true || me["name"] != "root" {
		t.Fatalf("expected admin root, got %v", me)
	}
	testutil.Expect(t, inst.Do("GET", "/api/v1/blob-stores", access, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("GET", "/api/v1/blob-stores", admin, nil), http.StatusOK)
}

func TestOIDCLoginFlowAndCSRF(t *testing.T) {
	idp := oidctest.New(t)
	inst := testutil.New(t, withIdP(idp))
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(inst.URL + "/auth/login?return=/repositories")
	if err != nil {
		t.Fatal(err)
	}
	testutil.Body(resp)
	if resp.Request.URL.Path != "/repositories" {
		t.Fatalf("expected redirect back to /repositories, ended at %s", resp.Request.URL)
	}
	resp, _ = client.Get(inst.URL + "/api/v1/me")
	var me map[string]any
	_ = json.Unmarshal([]byte(testutil.Expect(t, resp, http.StatusOK)), &me)
	if me["name"] != "alice" || !strings.Contains(toJSON(me["groups"]), "devs") {
		t.Fatalf("unexpected session principal: %v", me)
	}

	// Cookie-authenticated mutations require the CSRF header.
	body := `{"name":"laptop"}`
	resp, _ = client.Post(inst.URL+"/api/v1/tokens", "application/json", strings.NewReader(body))
	testutil.Expect(t, resp, http.StatusForbidden)
	req, _ := http.NewRequest("POST", inst.URL+"/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Entrepot-CSRF", "1")
	resp, _ = client.Do(req)
	var created struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal([]byte(testutil.Expect(t, resp, http.StatusCreated)), &created)
	if !strings.HasPrefix(created.Secret, "ent_") {
		t.Fatalf("unexpected token %q", created.Secret)
	}
	// The personal token authenticates as alice.
	_ = json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", "/api/v1/me", created.Secret, nil), http.StatusOK)), &me)
	if me["name"] != "alice" {
		t.Fatalf("token principal: %v", me)
	}
	// Logout clears the session.
	noRedirect := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ = noRedirect.Get(inst.URL + "/auth/logout")
	testutil.Body(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, idp.URL+"/logout") {
		t.Fatalf("expected IdP logout redirect, got %q", loc)
	}
	resp, _ = client.Get(inst.URL + "/api/v1/me")
	_ = json.Unmarshal([]byte(testutil.Expect(t, resp, http.StatusOK)), &me)
	if me["kind"] != "anonymous" {
		t.Fatalf("expected anonymous after logout, got %v", me)
	}
}

func TestTokenScopesAndAnonymous(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("public", "raw", "hosted", map[string]any{"anonymousRead": true})
	inst.CreateRepo("private", "raw", "hosted", nil)
	testutil.Expect(t, inst.Do("PUT", "/repository/public/f", testutil.BootstrapToken, strings.NewReader("p")), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", "/repository/private/f", testutil.BootstrapToken, strings.NewReader("p")), http.StatusCreated)

	testutil.Expect(t, inst.Do("GET", "/repository/public/f", "", nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/private/f", "", nil), http.StatusUnauthorized)

	// Anonymous listing only shows public repositories.
	var repos []map[string]any
	_ = json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", "/api/v1/repositories", "", nil), http.StatusOK)), &repos)
	if len(repos) != 1 || repos[0]["name"] != "public" {
		t.Fatalf("anonymous repository list: %v", repos)
	}

	// A read-scoped admin token cannot write.
	inst.JSON("POST", "/service-accounts", map[string]any{"name": "robot"}, http.StatusCreated, nil)
	inst.JSON("POST", "/role-bindings", map[string]any{"role": "admin", "subjectType": "user", "subject": "sa:robot"}, http.StatusCreated, nil)
	var tok struct {
		Secret string `json:"secret"`
	}
	inst.JSON("POST", "/service-accounts/robot/tokens", map[string]any{"name": "ro", "scopes": []string{"read"}}, http.StatusCreated, &tok)
	testutil.Expect(t, inst.Do("GET", "/repository/private/f", tok.Secret, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("PUT", "/repository/private/g", tok.Secret, strings.NewReader("x")), http.StatusForbidden)
	testutil.Expect(t, inst.Do("GET", "/api/v1/blob-stores", tok.Secret, nil), http.StatusForbidden)
	// ... and cannot mint a broader token.
	resp := inst.Do("POST", "/api/v1/tokens", tok.Secret, bytes.NewReader([]byte(`{"name":"x","scopes":["write"]}`)))
	testutil.Expect(t, resp, http.StatusForbidden)

	// Revoked tokens stop working.
	var list []map[string]any
	inst.JSON("GET", "/service-accounts/robot/tokens", nil, http.StatusOK, &list)
	inst.JSON("DELETE", "/service-accounts/robot/tokens/"+list[0]["id"].(string), nil, http.StatusNoContent, nil)
	testutil.Expect(t, inst.Do("GET", "/repository/private/f", tok.Secret, nil), http.StatusUnauthorized)

	// Garbage credentials are rejected rather than treated as anonymous.
	testutil.Expect(t, inst.Do("GET", "/repository/public/f", "ent_bogus", nil), http.StatusUnauthorized)
}

func TestAnonymousAccessDisabled(t *testing.T) {
	inst := testutil.New(t, func(c *config.Config) { c.Auth.AnonymousAccess = false })
	inst.CreateRepo("public", "raw", "hosted", map[string]any{"anonymousRead": true})
	testutil.Expect(t, inst.Do("PUT", "/repository/public/f", testutil.BootstrapToken, strings.NewReader("p")), http.StatusCreated)
	testutil.Expect(t, inst.Do("GET", "/repository/public/f", "", nil), http.StatusUnauthorized)
}

func TestAuditAndDeleteRepository(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("tmp", "raw", "hosted", nil)
	testutil.Expect(t, inst.Do("PUT", "/repository/tmp/f", testutil.BootstrapToken, strings.NewReader("data")), http.StatusCreated)
	inst.JSON("DELETE", "/repositories/tmp", nil, http.StatusNoContent, nil)
	var removed map[string]int
	inst.JSON("POST", "/maintenance/gc", nil, http.StatusOK, &removed)
	if removed["removed"] != 1 {
		t.Fatalf("expected the orphaned blob to be collected, got %v", removed)
	}
	var events []map[string]any
	inst.JSON("GET", "/audit-events", nil, http.StatusOK, &events)
	got := toJSON(events)
	for _, want := range []string{"repository.create", "repository.delete", "maintenance.gc"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit log missing %s", want)
		}
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestHostedRedeployDefaults(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("img", "docker", "hosted", nil)
	inst.CreateRepo("libs", "npm", "hosted", nil)
	var img, libs struct {
		Hosted struct {
			AllowRedeploy bool `json:"allowRedeploy"`
		} `json:"hosted"`
	}
	inst.JSON("GET", "/repositories/img", nil, http.StatusOK, &img)
	inst.JSON("GET", "/repositories/libs", nil, http.StatusOK, &libs)
	if !img.Hosted.AllowRedeploy || libs.Hosted.AllowRedeploy {
		t.Fatalf("docker should default to movable tags, others to immutable: docker=%v npm=%v",
			img.Hosted.AllowRedeploy, libs.Hosted.AllowRedeploy)
	}
}
