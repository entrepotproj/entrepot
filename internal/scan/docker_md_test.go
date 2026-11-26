package scan_test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/entrepotproj/entrepot/internal/testutil"
)

// layerImage is an image whose layer blobs are exactly contents
// (uncompressed), so the fake MetaDefender sees its markers.
func layerImage(t *testing.T, contents ...string) v1.Image {
	t.Helper()
	img := empty.Image
	for _, c := range contents {
		var err error
		img, err = mutate.AppendLayers(img, static.NewLayer([]byte(c), types.OCIUncompressedLayer))
		if err != nil {
			t.Fatal(err)
		}
	}
	return img
}

func layerDigest(t *testing.T, img v1.Image, i int) string {
	t.Helper()
	ls, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	d, err := ls[i].Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

func platformIndex(t *testing.T, imgs map[string]v1.Image) v1.ImageIndex {
	t.Helper()
	var idx v1.ImageIndex = empty.Index
	for _, arch := range []string{"amd64", "arm64"} {
		img, ok := imgs[arch]
		if !ok {
			continue
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	return idx
}

func summaryOf(t *testing.T, inst *testutil.Instance, componentID string) map[string]any {
	t.Helper()
	var raw []byte
	if err := inst.App.Pool.QueryRow(context.Background(), `SELECT summary FROM scan_results WHERE component_id=$1
		ORDER BY scanned_at DESC LIMIT 1`, componentID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var sm map[string]any
	_ = json.Unmarshal(raw, &sm)
	return sm
}

// Docker images are sent to MetaDefender layer by layer. A layer shared
// with an image analysed before is not uploaded again; an infected layer
// blocks the tag and its manifests by digest.
func TestMetaDefenderDockerLayers(t *testing.T) {
	inst, srv := newMDInst(t)
	inst.CreateRepo("docker-md", "docker", "hosted", scanSettings([]string{"md"}, "quarantine", map[string]any{"blockUntilScanned": true}))
	startWorkers(t, inst)

	base := "base layer shared by every image"
	app := layerImage(t, base, "app layer v1")
	if err := remote.Write(imageRef(t, inst, "docker-md/team/app:v1"), app, adminAuth); err != nil {
		t.Fatalf("push: %v", err)
	}
	c := findComponent(t, inst, "docker-md", "team/app", "v1")
	waitState(t, inst, c.ID, "clean")
	if up, _, _ := srv.Counts(); up != 2 {
		t.Fatalf("uploads after app: %d", up)
	}
	files := mdResults(t, inst, c.ID).Results[0].Files
	if len(files) != 2 || files[0].Name != "layer "+layerDigest(t, app, 0)[:19] {
		t.Fatalf("files: %+v", files)
	}

	other := layerImage(t, base, "other layer")
	if err := remote.Write(imageRef(t, inst, "docker-md/team/other:v1"), other, adminAuth); err != nil {
		t.Fatal(err)
	}
	co := findComponent(t, inst, "docker-md", "team/other", "v1")
	waitState(t, inst, co.ID, "clean")
	if up, _, _ := srv.Counts(); up != 3 {
		t.Fatalf("shared base layer uploaded again: %d uploads", up)
	}
	if f := mdResults(t, inst, co.ID).Results[0].Files; !f[0].Cached || f[1].Cached {
		t.Fatalf("files: %+v", f)
	}

	evil := layerImage(t, base, "dropper X-MDFAKE-MALWARE")
	if err := remote.Write(imageRef(t, inst, "docker-md/team/evil:v1"), evil, adminAuth); err != nil {
		t.Fatal(err)
	}
	ce := findComponent(t, inst, "docker-md", "team/evil", "v1")
	waitState(t, inst, ce.ID, "vulnerable")
	dg, _ := evil.Digest()
	short := strings.TrimPrefix(layerDigest(t, evil, 1), "sha256:")[:12]
	for _, ref := range []string{"v1", dg.String()} {
		b := testutil.Expect(t, inst.Do("GET", "/v2/docker-md/team/evil/manifests/"+ref, testutil.BootstrapToken, nil), http.StatusForbidden)
		if !strings.Contains(b, "MALWARE:Virus eicar test file detected by md in layer sha256:"+short+" (team/evil:v1)") {
			t.Fatalf("%s: %s", ref, b)
		}
	}
	if sm := summaryOf(t, inst, ce.ID); sm["digest"] != dg.String() {
		t.Fatalf("summary: %v", sm)
	}

	// A multi-platform index: layers shared by the platforms are sent once
	// and name every platform.
	amd := layerImage(t, base, "amd64 binaries")
	arm := layerImage(t, base, "arm64 binaries")
	if err := remote.WriteIndex(imageRef(t, inst, "docker-md/team/multi:v1"), platformIndex(t, map[string]v1.Image{"amd64": amd, "arm64": arm}), adminAuth); err != nil {
		t.Fatal(err)
	}
	cm := findComponent(t, inst, "docker-md", "team/multi", "v1")
	waitState(t, inst, cm.ID, "clean")
	files = mdResults(t, inst, cm.ID).Results[0].Files
	if len(files) != 3 || !strings.HasSuffix(files[0].Name, "(linux/amd64, linux/arm64)") || !strings.HasSuffix(files[2].Name, "(linux/arm64)") {
		t.Fatalf("index files: %+v", files)
	}
	if sm := summaryOf(t, inst, cm.ID); len(sm["digests"].([]any)) != 3 || len(sm["platforms"].([]any)) != 2 || sm["skippedDigests"] != nil {
		t.Fatalf("index summary: %v", sm)
	}
}

// A proxy scans the platforms it has cached. Pulling a platform the scan
// left out holds the pull while the image is scanned again with it.
func TestMetaDefenderDockerProxyPlatforms(t *testing.T) {
	upstream := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(upstream.Close)
	base := "base layer shared by every platform"
	amd := layerImage(t, base, "amd64 binaries")
	arm := layerImage(t, base, "arm64 binaries X-MDFAKE-MALWARE")
	idx := platformIndex(t, map[string]v1.Image{"amd64": amd, "arm64": arm})
	upRef, err := name.ParseReference(strings.TrimPrefix(upstream.URL, "http://")+"/org/multi:1", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(upRef, idx); err != nil {
		t.Fatal(err)
	}

	inst, srv := newMDInst(t)
	settings := scanSettings([]string{"md"}, "quarantine", map[string]any{"blockUntilScanned": true, "holdSeconds": 30})
	settings["proxy"] = map[string]any{"remoteUrl": upstream.URL}
	inst.CreateRepo("hub-md", "docker", "proxy", settings)
	startWorkers(t, inst)

	// The tag (index) is held while linux/amd64 is scanned, then served.
	r := await(t, getAsync(inst, "/v2/hub-md/org/multi/manifests/1"))
	if r.code != http.StatusOK {
		t.Fatalf("tag pull: %d %s", r.code, r.body)
	}
	c := findComponent(t, inst, "hub-md", "org/multi", "1")
	im, _ := idx.IndexManifest()
	armDigest := im.Manifests[1].Digest.String()
	sm := summaryOf(t, inst, c.ID)
	if skipped, _ := sm["skippedDigests"].([]any); len(skipped) != 1 || skipped[0] != armDigest {
		t.Fatalf("summary: %v", sm)
	}
	if up, _, _ := srv.Counts(); up != 2 {
		t.Fatalf("uploads: %d", up)
	}

	// Pulling linux/arm64 rescans with both platforms: its layer is infected.
	r = await(t, getAsync(inst, "/v2/hub-md/org/multi/manifests/"+armDigest))
	if r.code != http.StatusForbidden || !strings.Contains(r.body, "MALWARE:Virus eicar test file") || !strings.Contains(r.body, "(linux/arm64)") {
		t.Fatalf("arm64 pull: %d %s", r.code, r.body)
	}
	testutil.Expect(t, inst.Do("GET", "/v2/hub-md/org/multi/manifests/1", testutil.BootstrapToken, nil), http.StatusForbidden)
	if up, _, _ := srv.Counts(); up != 3 {
		t.Fatalf("uploads after rescan: %d (shared layers re-sent?)", up)
	}
	sm = summaryOf(t, inst, c.ID)
	if sm["skippedDigests"] != nil || len(sm["platforms"].([]any)) != 2 {
		t.Fatalf("summary after rescan: %v", sm)
	}
}

// Without strict verdicts (Trivy only, no blockOnError) a pull of a
// platform that was not scanned does not trigger a rescan, as before.
func TestDockerProxyPlatformsLax(t *testing.T) {
	upstream := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(upstream.Close)
	idx := platformIndex(t, map[string]v1.Image{"amd64": layerImage(t, "a"), "arm64": layerImage(t, "b")})
	upRef, _ := name.ParseReference(strings.TrimPrefix(upstream.URL, "http://")+"/org/multi:1", name.Insecure)
	if err := remote.WriteIndex(upRef, idx); err != nil {
		t.Fatal(err)
	}
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	settings := scanSettings([]string{"trivy"}, "quarantine", nil)
	settings["proxy"] = map[string]any{"remoteUrl": upstream.URL}
	inst.CreateRepo("hub-lax", "docker", "proxy", settings)
	startWorkers(t, inst)

	testutil.Expect(t, inst.Do("GET", "/v2/hub-lax/org/multi/manifests/1", testutil.BootstrapToken, nil), http.StatusOK)
	c := findComponent(t, inst, "hub-lax", "org/multi", "1")
	waitState(t, inst, c.ID, "vulnerable")
	im, _ := idx.IndexManifest()
	before := contentRev(t, inst, c.ID)
	inst.Do("GET", "/v2/hub-lax/org/multi/manifests/"+im.Manifests[1].Digest.String(), testutil.BootstrapToken, nil).Body.Close()
	if after := contentRev(t, inst, c.ID); after != before {
		t.Fatalf("lax repository rescanned: rev %d -> %d", before, after)
	}
}
