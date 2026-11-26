package scan

import (
	"reflect"
	"testing"

	"github.com/entrepotproj/entrepot/internal/formats/docker"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

func TestUncachedPlatforms(t *testing.T) {
	ms := []docker.ImageManifest{
		{Digest: "sha256:a", Platform: "linux/amd64", Local: true},
		{Digest: "sha256:b", Platform: "linux/arm64"},
		{Digest: "sha256:c", Platform: "linux/s390x"},
	}
	proxy := &repo.Repository{Repository: &store.Repository{Kind: repo.KindProxy}}
	sel := selectPlatforms(proxy, ms)
	if len(sel) != 1 || sel[0].Digest != "sha256:a" {
		t.Fatalf("selected: %+v", sel)
	}
	if got := uncachedPlatforms(proxy, ms, sel); !reflect.DeepEqual(got, []string{"sha256:b", "sha256:c"}) {
		t.Fatalf("skipped: %v", got)
	}
	// Nothing cached: linux/amd64 is scanned (and cached by the scan).
	ms[0].Local = false
	sel = selectPlatforms(proxy, ms)
	if got := uncachedPlatforms(proxy, ms, sel); len(sel) != 1 || sel[0].Digest != "sha256:a" ||
		!reflect.DeepEqual(got, []string{"sha256:b", "sha256:c"}) {
		t.Fatalf("fallback: %+v %v", sel, got)
	}
	// Hosted repositories scan every platform (up to the limit, which is
	// not reported as skipped).
	hosted := &repo.Repository{Repository: &store.Repository{Kind: repo.KindHosted}}
	if got := uncachedPlatforms(hosted, ms, selectPlatforms(hosted, ms)); got != nil {
		t.Fatalf("hosted skipped: %v", got)
	}
}

func TestLayerExt(t *testing.T) {
	for mt, want := range map[string]string{
		"application/vnd.oci.image.layer.v1.tar+gzip":          ".tar.gz",
		"application/vnd.docker.image.rootfs.diff.tar.gzip":    ".tar.gz",
		"application/vnd.oci.image.layer.v1.tar+zstd":          ".tar.zst",
		"application/vnd.oci.image.layer.v1.tar":               ".tar",
		"application/vnd.docker.image.rootfs.foreign.diff.tar": ".tar",
		"": ".tar.gz",
	} {
		if got := layerExt(mt); got != want {
			t.Errorf("layerExt(%q) = %q, want %q", mt, got, want)
		}
	}
}
