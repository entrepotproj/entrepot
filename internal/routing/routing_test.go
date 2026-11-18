package routing_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/geoffo-dev/package-repository/internal/routing"
	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func TestSubject(t *testing.T) {
	cases := []struct{ format, path, want string }{
		{"npm", "left-pad/package.json", "left-pad"},
		{"npm", "left-pad/-/left-pad-1.3.0.tgz", "left-pad"},
		{"npm", "@acme/widgets/package.json", "@acme/widgets"},
		{"npm", "@acme%2fwidgets", "@acme/widgets"},
		{"npm", "@acme%2Fwidgets/1.0.0", "@acme/widgets"},
		{"npm", "@acme/widgets/-/widgets-1.0.0.tgz", "@acme/widgets"},
		{"pypi", "simple/Acme_Utils", "acme-utils"},
		{"pypi", "simple/acme-utils/", "acme-utils"},
		{"pypi", "packages/acme-utils/1.0/acme_utils-1.0-py3-none-any.whl", "acme-utils"},
		{"docker", "library/alpine/_manifests/sha256:abc", "library/alpine"},
		{"docker", "acme/api/_tags/v1", "acme/api"},
		{"docker", "acme/team/api/_blobs/sha256:abc", "acme/team/api"},
		{"helm", "charts/acme-chart-1.2.3.tgz", "acme-chart"},
		{"helm", "charts/nginx-1.2.3-rc.1+b.tgz.prov", "nginx"},
		{"raw", "dir/file.txt", "dir/file.txt"},
	}
	for _, c := range cases {
		got, ok := routing.Subject(c.format, c.path)
		if !ok || got != c.want {
			t.Errorf("Subject(%s, %s) = %q, %v; want %q", c.format, c.path, got, ok, c.want)
		}
	}
	if _, ok := routing.Subject("helm", "index.yaml"); ok {
		t.Error("helm index.yaml should not be subject to routing")
	}
}

func TestEvaluate(t *testing.T) {
	block, err := routing.Compile("b", "block", []string{"^@acme/", "^acme-"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, m := block.Evaluate("@acme/widgets"); ok || m != "^@acme/" {
		t.Errorf("block @acme: %v %q", ok, m)
	}
	if ok, m := block.Evaluate("left-pad"); !ok || m != "" {
		t.Errorf("block left-pad: %v %q", ok, m)
	}
	allow, _ := routing.Compile("a", "allow", []string{"^left-"})
	if ok, _ := allow.Evaluate("left-pad"); !ok {
		t.Error("allow left-pad")
	}
	if ok, _ := allow.Evaluate("right-pad"); ok {
		t.Error("allow right-pad")
	}
	for _, bad := range [][]string{nil, {""}, {"("}} {
		if _, err := routing.Compile("x", "block", bad); err == nil {
			t.Errorf("Compile(%q) succeeded", bad)
		}
	}
	if _, err := routing.Compile("x", "deny", []string{"a"}); err == nil {
		t.Error("invalid mode accepted")
	}
}

func TestRoutingRules(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.EscapedPath()]++
		mu.Unlock()
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch r.URL.EscapedPath() {
		case "/left-pad", "/@acme%2fwidgets", "/right-pad":
			fmt.Fprintf(w, `{"name":%q,"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":%q,"version":"1.0.0","dist":{"tarball":"x"}}}}`, name, name)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	hit := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[p]
	}

	inst := testutil.New(t)
	// Validation.
	for _, bad := range []map[string]any{
		{"name": "x", "mode": "deny", "matchers": []string{"a"}},
		{"name": "x", "mode": "block", "matchers": []string{}},
		{"name": "x", "mode": "block", "matchers": []string{"("}},
		{"name": "X!", "mode": "block", "matchers": []string{"a"}},
	} {
		b, _ := json.Marshal(bad)
		testutil.Expect(t, inst.Do("POST", "/api/v1/routing-rules", testutil.BootstrapToken, strings.NewReader(string(b)), "Content-Type", "application/json"), http.StatusBadRequest)
	}
	inst.JSON("POST", "/routing-rules", map[string]any{"name": "no-acme", "description": "Internal scope", "mode": "block",
		"matchers": []string{"^@acme/"}}, http.StatusCreated, nil)
	inst.JSON("POST", "/routing-rules", map[string]any{"name": "no-acme", "mode": "block", "matchers": []string{"x"}}, http.StatusConflict, nil)
	var res struct {
		Allowed bool   `json:"allowed"`
		Matched string `json:"matched"`
	}
	inst.JSON("POST", "/routing-rules/no-acme/test", map[string]any{"path": "@acme/widgets"}, http.StatusOK, &res)
	if res.Allowed || res.Matched != "^@acme/" {
		t.Fatalf("test: %+v", res)
	}
	res.Matched = ""
	inst.JSON("POST", "/routing-rules/no-acme/test", map[string]any{"path": "left-pad"}, http.StatusOK, &res)
	if !res.Allowed || res.Matched != "" {
		t.Fatalf("test: %+v", res)
	}
	testutil.Expect(t, inst.Do("GET", "/api/v1/routing-rules", inst.Token("viewer", "viewer", "*"), nil), http.StatusForbidden)

	// Unknown rules are rejected on repositories.
	resp := inst.Do("POST", "/api/v1/repositories", testutil.BootstrapToken, strings.NewReader(fmt.Sprintf(
		`{"name":"bad","format":"npm","kind":"proxy","blobStore":"default","proxy":{"remoteUrl":%q,"routingRule":"nope"}}`, upstream.URL)),
		"Content-Type", "application/json")
	testutil.Expect(t, resp, http.StatusBadRequest)

	inst.CreateRepo("npmjs", "npm", "proxy", map[string]any{"anonymousRead": true,
		"proxy": map[string]any{"remoteUrl": upstream.URL, "routingRule": "no-acme"}})
	testutil.Expect(t, inst.Do("GET", "/repository/npmjs/@acme%2fwidgets", "", nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/npmjs/@acme/widgets/-/widgets-1.0.0.tgz", "", nil), http.StatusNotFound)
	if hit("/@acme%2fwidgets") != 0 {
		t.Fatal("blocked package was requested upstream")
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npmjs/left-pad", "", nil), http.StatusOK)

	var rule struct {
		Repositories []string `json:"repositories"`
		Description  string   `json:"description"`
	}
	inst.JSON("GET", "/routing-rules/no-acme", nil, http.StatusOK, &rule)
	if len(rule.Repositories) != 1 || rule.Repositories[0] != "npmjs" || rule.Description != "Internal scope" {
		t.Fatalf("rule: %+v", rule)
	}
	inst.JSON("DELETE", "/routing-rules/no-acme", nil, http.StatusConflict, nil)

	// Updates apply immediately: allow mode only lets matching names through.
	inst.JSON("PUT", "/routing-rules/no-acme", map[string]any{"mode": "allow", "matchers": []string{"^left-", "^@acme/"}}, http.StatusOK, nil)
	testutil.Expect(t, inst.Do("GET", "/repository/npmjs/right-pad", "", nil), http.StatusNotFound)
	if hit("/right-pad") != 0 {
		t.Fatal("non-allowed package was requested upstream")
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npmjs/@acme%2fwidgets", "", nil), http.StatusOK)
	inst.JSON("PUT", "/routing-rules/no-acme", map[string]any{"name": "renamed", "mode": "allow", "matchers": []string{"a"}}, http.StatusBadRequest, nil)

	// Once no repository uses it, the rule can be deleted.
	inst.JSON("PUT", "/repositories/npmjs", map[string]any{"name": "npmjs", "format": "npm", "kind": "proxy", "blobStore": "default",
		"anonymousRead": true, "proxy": map[string]any{"remoteUrl": upstream.URL}}, http.StatusOK, nil)
	inst.JSON("DELETE", "/routing-rules/no-acme", nil, http.StatusNoContent, nil)
	inst.JSON("GET", "/routing-rules/no-acme", nil, http.StatusNotFound, nil)
	var rules []any
	inst.JSON("GET", "/routing-rules", nil, http.StatusOK, &rules)
	if len(rules) != 0 {
		t.Fatalf("rules: %+v", rules)
	}
}
