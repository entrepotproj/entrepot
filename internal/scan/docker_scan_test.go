package scan_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/validate"

	"github.com/geoffo-dev/package-repository/internal/formats/docker"
	"github.com/geoffo-dev/package-repository/internal/scan"
	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func imageRef(t *testing.T, inst *testutil.Instance, s string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(strings.TrimPrefix(inst.URL, "http://")+"/"+s, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var adminAuth = remote.WithAuth(&authn.Basic{Username: "docker", Password: testutil.BootstrapToken})

// Docker images are exported as OCI layouts and scanned; quarantine blocks
// manifests (by tag and digest) but not layers.
func TestDockerImageScan(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("docker-h", "docker", "hosted", scanSettings([]string{"trivy"}, "quarantine", nil))
	startWorkers(t, inst)

	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(imageRef(t, inst, "docker-h/team/app:v1"), img, adminAuth); err != nil {
		t.Fatalf("push: %v", err)
	}
	dg, _ := img.Digest()
	c := findComponent(t, inst, "docker-h", "team/app", "v1")
	s := waitState(t, inst, c.ID, "vulnerable")
	if !s.Quarantined || len(s.Results[0].Findings) != 3 || s.Results[0].Target != "team/app:v1@"+dg.String() ||
		!strings.Contains(s.QuarantineReason, "CVE-2023-5363 (critical) in libcrypto3 3.1.0-r4 in team/app:v1") {
		t.Fatalf("scans: %+v", s)
	}
	body := testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/app/manifests/v1", testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "CVE-2023-5363") {
		t.Fatalf("body: %s", body)
	}
	testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/app/manifests/"+dg.String(), testutil.BootstrapToken, nil), http.StatusForbidden)
	layers, _ := img.Layers()
	ld, _ := layers[0].Digest()
	testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/app/blobs/"+ld.String(), testutil.BootstrapToken, nil), http.StatusOK)

	// The export helper writes a valid OCI layout.
	ctx := context.Background()
	rp, err := inst.App.Repos.Get(ctx, "docker-h")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := docker.ExportOCILayout(ctx, inst.App.Repos, rp, "team/app", dg.String(), dir); err != nil {
		t.Fatal(err)
	}
	lp, err := layout.FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	limg, err := lp.Image(dg)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Image(limg); err != nil {
		t.Fatalf("exported image invalid: %v", err)
	}

	// A multi-platform index: every platform image is scanned; platform
	// manifests pulled by digest are blocked too.
	idx, err := random.Index(512, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(imageRef(t, inst, "docker-h/team/multi:v2"), idx, adminAuth); err != nil {
		t.Fatalf("push index: %v", err)
	}
	c2 := findComponent(t, inst, "docker-h", "team/multi", "v2")
	waitState(t, inst, c2.ID, "vulnerable")
	var raw []byte
	if err := inst.App.Pool.QueryRow(ctx, `SELECT summary FROM scan_results WHERE component_id=$1`, c2.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var sm struct {
		Digest  string   `json:"digest"`
		Digests []string `json:"digests"`
	}
	_ = json.Unmarshal(raw, &sm)
	im, _ := idx.IndexManifest()
	idg, _ := idx.Digest()
	if len(sm.Digests) != 3 || sm.Digest != idg.String() {
		t.Fatalf("summary: %s", raw)
	}
	testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/multi/manifests/"+im.Manifests[1].Digest.String(), testutil.BootstrapToken, nil),
		http.StatusForbidden)
	idir := t.TempDir()
	if err := docker.ExportOCILayout(ctx, inst.App.Repos, rp, "team/multi", sm.Digest, idir); err != nil {
		t.Fatal(err)
	}
	lp, _ = layout.FromPath(idir)
	lidx, err := lp.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	tm, _ := lidx.IndexManifest()
	child, err := lidx.ImageIndex(tm.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Index(child); err != nil {
		t.Fatalf("exported index invalid: %v", err)
	}

	// Waiving the critical finding releases the image (medium remains).
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "CVE-2023-5363", "componentPattern": "team/*"}, http.StatusCreated, nil)
	testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/app/manifests/v1", testutil.BootstrapToken, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/v2/docker-h/team/multi/manifests/v2", testutil.BootstrapToken, nil), http.StatusOK)
	pulled, err := remote.Image(imageRef(t, inst, "docker-h/team/app:v1"), adminAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Image(pulled); err != nil {
		t.Fatal(err)
	}
}

// Webhook scanners get Docker images as an OCI layout tar.
func TestDockerWebhookArtifact(t *testing.T) {
	var tarball []byte
	hook := newFakeWebhook(t, "k", func(req scan.WebhookRequest) any {
		return map[string]any{"findings": []any{}}
	})
	inst := newInst(t)
	inst.JSON("POST", "/scanners", map[string]any{"name": "hook", "type": "webhook",
		"webhook": map[string]any{"url": hook.URL, "secret": "k"}}, http.StatusCreated, nil)
	inst.CreateRepo("docker-w", "docker", "hosted", scanSettings([]string{"hook"}, "warn", nil))
	startWorkers(t, inst)
	img, _ := random.Image(256, 1)
	if err := remote.Write(imageRef(t, inst, "docker-w/app:1"), img, adminAuth); err != nil {
		t.Fatal(err)
	}
	c := findComponent(t, inst, "docker-w", "app", "1")
	waitState(t, inst, c.ID, "clean")
	hook.mu.Lock()
	req := hook.reqs[0]
	tarball = hook.art[req.JobID]
	hook.mu.Unlock()
	dg, _ := img.Digest()
	if req.Target != "image" || req.Component.Image != "app" || req.Component.Digest != dg.String() {
		t.Fatalf("request: %+v", req)
	}
	files := untar(t, tarball)
	if _, ok := files["oci-layout"]; !ok {
		t.Fatalf("tar: %v", keys(files))
	}
	if _, ok := files["blobs/sha256/"+dg.Hex]; !ok || !strings.Contains(string(files["index.json"]), dg.String()) {
		t.Fatalf("tar: %v", keys(files))
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
