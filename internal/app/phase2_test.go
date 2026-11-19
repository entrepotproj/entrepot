package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/secrets"
	"github.com/entrepotproj/entrepot/internal/store"
	"github.com/entrepotproj/entrepot/internal/testutil"
	"github.com/entrepotproj/entrepot/internal/testutil/oidctest"
)

// Proxy passwords are sealed in Postgres but still sent to the upstream.
func TestProxyPasswordSealedAtRest(t *testing.T) {
	var gotPass atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		gotPass.Store(p)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("remote", "raw", "proxy", map[string]any{
		"proxy": map[string]any{"remoteUrl": upstream.URL, "username": "u", "password": "s3cret-password"},
	})
	var raw []byte
	if err := inst.App.Pool.QueryRow(context.Background(), `SELECT config FROM repositories WHERE name='remote'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret-password") || !strings.Contains(string(raw), "enc:v1:") {
		t.Fatalf("password not sealed at rest: %s", raw)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/remote/file", testutil.BootstrapToken, nil), http.StatusOK)
	if gotPass.Load() != "s3cret-password" {
		t.Fatalf("upstream got password %v", gotPass.Load())
	}
	// The API never returns the password, and an update without it keeps it.
	var out map[string]any
	inst.JSON("GET", "/repositories/remote", nil, http.StatusOK, &out)
	if strings.Contains(toJSON(out), "s3cret") || strings.Contains(toJSON(out), "enc:v1") {
		t.Fatalf("password leaked: %v", out)
	}
	inst.JSON("PUT", "/repositories/remote", map[string]any{
		"name": "remote", "format": "raw", "kind": "proxy", "blobStore": "default",
		"proxy": map[string]any{"remoteUrl": upstream.URL, "username": "u", "metadataTtlSeconds": 1},
	}, http.StatusOK, nil)
	inst.App.Repos.Invalidate("remote")
	time.Sleep(1100 * time.Millisecond)
	testutil.Expect(t, inst.Do("GET", "/repository/remote/file", testutil.BootstrapToken, nil), http.StatusOK)
	if gotPass.Load() != "s3cret-password" {
		t.Fatalf("password lost on update: %v", gotPass.Load())
	}
}

// Plaintext secrets written before encryption are sealed on startup.
func TestResealPlaintextSecrets(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("legacy", "raw", "proxy", map[string]any{"proxy": map[string]any{"remoteUrl": "https://example.com"}})
	ctx := context.Background()
	if _, err := inst.App.Pool.Exec(ctx, `UPDATE repositories SET config = jsonb_set(config, '{proxy,password}', '"plain-old"') WHERE name='legacy'`); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.New(inst.Config.SecretsKey())
	// Simulate a restart by running the startup migration through a second app.
	inst2 := testutil.Reopen(t, inst)
	var raw []byte
	_ = inst2.App.Pool.QueryRow(ctx, `SELECT config->'proxy'->>'password' FROM repositories WHERE name='legacy'`).Scan(&raw)
	if !secrets.IsSealed(string(raw)) {
		t.Fatalf("not resealed: %s", raw)
	}
	if pt, err := box.Open(string(raw)); err != nil || pt != "plain-old" {
		t.Fatalf("open: %q %v", pt, err)
	}
}

// Assets record their uploader, including GitLab CI claims.
func TestUploaderRecorded(t *testing.T) {
	gl := oidctest.New(t)
	inst := testutil.New(t, func(c *config.Config) {
		c.Auth.GitLab = []config.GitLabSpec{{Name: "gitlab", IssuerURL: gl.URL}}
	})
	inst.CreateRepo("files", "raw", "hosted", nil)
	inst.JSON("POST", "/gitlab-trust-policies", map[string]any{
		"name": "all", "gitlab": "gitlab", "conditions": map[string]string{"project_path": "**"},
	}, http.StatusCreated, nil)
	inst.JSON("POST", "/role-bindings", map[string]any{"role": "developer", "subjectType": "gitlab_policy", "subject": "all"}, http.StatusCreated, nil)
	tok := gl.Mint(t, map[string]any{"aud": inst.URL, "project_path": "team/app", "project_id": "77", "ref": "main",
		"sha": "abc123", "pipeline_id": "9", "job_id": "42"}, time.Minute)
	testutil.Expect(t, inst.Do("PUT", "/repository/files/app.tgz", tok, strings.NewReader("x")), http.StatusCreated)

	var page struct {
		Items []map[string]any `json:"items"`
	}
	inst.JSON("GET", "/repositories/files/assets", nil, http.StatusOK, &page)
	u := toJSON(page.Items[0]["uploader"])
	for _, want := range []string{`"kind":"gitlab"`, `"gitlab":"gitlab"`, `"sha":"abc123"`, `"project_id":"77"`} {
		if !strings.Contains(u, want) {
			t.Fatalf("uploader %s missing %s", u, want)
		}
	}
}

// The quarantine gate blocks downloads; the stored hook sees components.
func TestQuarantineGateAndStoredHook(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("libs", "npm", "hosted", nil)
	var events atomic.Int32
	inst.App.Repos.OnComponentStored(func(ctx context.Context, ev repo.StoredEvent) {
		if ev.ComponentID != "" && ev.Changed {
			events.Add(1)
		}
	})
	inst.App.Repos.QuarantineCheck = func(ctx context.Context, rp *repo.Repository, a *store.Asset) (bool, string) {
		return strings.HasSuffix(a.Path, ".tgz"), "CVE-0000-0001 (critical)"
	}
	pkg := map[string]any{
		"name": "demo", "versions": map[string]any{"1.0.0": map[string]any{"name": "demo", "version": "1.0.0",
			"dist": map[string]any{"tarball": "http://x/demo/-/demo-1.0.0.tgz"}}},
		"dist-tags":    map[string]string{"latest": "1.0.0"},
		"_attachments": map[string]any{"demo-1.0.0.tgz": map[string]any{"content_type": "application/octet-stream", "data": "aGVsbG8=", "length": 5}},
	}
	b, _ := json.Marshal(pkg)
	testutil.Expect(t, inst.Do("PUT", "/repository/libs/demo", testutil.BootstrapToken, strings.NewReader(string(b)), "Content-Type", "application/json"), http.StatusCreated)
	if events.Load() == 0 {
		t.Fatal("stored hook not called")
	}
	resp := inst.Do("GET", "/repository/libs/demo/-/demo-1.0.0.tgz", testutil.BootstrapToken, nil)
	body := testutil.Expect(t, resp, http.StatusForbidden)
	if !strings.Contains(body, "CVE-0000-0001") || resp.Header.Get("X-Entrepot-Quarantined") != "true" {
		t.Fatalf("unexpected quarantine response: %s", body)
	}
	// Metadata is not blocked.
	testutil.Expect(t, inst.Do("GET", "/repository/libs/demo", testutil.BootstrapToken, nil), http.StatusOK)
}
