package docker_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func TestDockerCleanupUntagged(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("dk", "docker", "hosted", nil)
	tok := testutil.BootstrapToken

	old, _ := random.Image(512, 2)
	if err := remote.Write(ref(t, inst, "dk/app:v1"), old, basic(tok)); err != nil {
		t.Fatal(err)
	}
	oldDigest, _ := old.Digest()
	// Move the tag: the first manifest becomes untagged.
	cur, _ := random.Image(512, 1)
	if err := remote.Write(ref(t, inst, "dk/app:v1"), cur, basic(tok)); err != nil {
		t.Fatal(err)
	}
	// A tagged index keeps its (untagged) children.
	idx, _ := random.Index(256, 1, 2)
	if err := remote.WriteIndex(ref(t, inst, "dk/multi:latest"), idx, basic(tok)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := inst.App.Pool.Exec(ctx, `UPDATE assets SET created_at = now() - interval '40 days'
		WHERE repository_id = (SELECT id FROM repositories WHERE name='dk')`); err != nil {
		t.Fatal(err)
	}
	// A recent untagged manifest (e.g. mid-push) is not touched.
	fresh, _ := random.Image(128, 1)
	freshDigest, _ := fresh.Digest()
	if err := remote.Write(ref(t, inst, "dk/app@"+freshDigest.String()), fresh, basic(tok)); err != nil {
		t.Fatal(err)
	}

	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "untagged", "format": "docker",
		"criteria": map[string]any{"untaggedOlderThanDays": 30}}, http.StatusCreated, nil)
	type result struct {
		DryRun     bool  `json:"dryRun"`
		Assets     int64 `json:"assets"`
		Bytes      int64 `json:"bytes"`
		Components []any `json:"components"`
	}
	var preview result
	inst.JSON("POST", "/cleanup-policies/untagged/preview?repository=dk", nil, http.StatusOK, &preview)
	// The old manifest, its config blob and its two layers.
	if !preview.DryRun || preview.Assets != 4 || preview.Bytes == 0 || len(preview.Components) != 0 {
		t.Fatalf("preview: %+v", preview)
	}
	if _, err := remote.Image(ref(t, inst, "dk/app@"+oldDigest.String()), basic(tok)); err != nil {
		t.Fatalf("dry run deleted content: %v", err)
	}
	var run result
	inst.JSON("POST", "/repositories/dk/cleanup?policy=untagged", nil, http.StatusOK, &run)
	if run.DryRun || run.Assets != 4 {
		t.Fatalf("run: %+v", run)
	}
	if _, err := remote.Image(ref(t, inst, "dk/app@"+oldDigest.String()), basic(tok)); err == nil {
		t.Fatal("untagged manifest still served")
	}
	img, err := remote.Image(ref(t, inst, "dk/app:v1"), basic(tok))
	if err != nil {
		t.Fatal(err)
	}
	pullAll(t, img)
	if got, want := mustDigest(img), mustDigest(cur); got != want {
		t.Fatalf("v1 is %s, want %s", got, want)
	}
	ii, err := remote.Index(ref(t, inst, "dk/multi:latest"), basic(tok))
	if err != nil {
		t.Fatal(err)
	}
	im, _ := ii.IndexManifest()
	for _, m := range im.Manifests {
		child, err := ii.Image(m.Digest)
		if err != nil {
			t.Fatal(err)
		}
		pullAll(t, child)
	}
	if _, err := remote.Image(ref(t, inst, "dk/app@"+freshDigest.String()), basic(tok)); err != nil {
		t.Fatalf("recent untagged manifest removed: %v", err)
	}
	// Nothing left to clean.
	inst.JSON("POST", "/cleanup-policies/untagged/preview?repository=dk", nil, http.StatusOK, &preview)
	if preview.Assets != 0 {
		t.Fatalf("second preview: %+v", preview)
	}
}
