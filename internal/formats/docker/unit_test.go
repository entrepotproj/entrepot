package docker

import (
	"testing"

	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

func proxyRepo(remote string) *repo.Repository {
	return &repo.Repository{
		Repository: &store.Repository{Name: "p", Kind: repo.KindProxy},
		Cfg:        repo.Config{Proxy: &repo.ProxyConfig{RemoteURL: remote}},
	}
}

func TestUpstreamNames(t *testing.T) {
	cases := []struct{ remote, image, wantImage, wantBase string }{
		{"https://registry-1.docker.io", "alpine", "library/alpine", "https://registry-1.docker.io"},
		{"https://registry-1.docker.io/", "library/alpine", "library/alpine", "https://registry-1.docker.io"},
		{"https://docker.io", "nginx", "library/nginx", "https://registry-1.docker.io"},
		{"https://index.docker.io/v2/", "bitnami/redis", "bitnami/redis", "https://registry-1.docker.io"},
		{"https://ghcr.io", "alpine", "alpine", "https://ghcr.io"},
		{"https://registry.gitlab.com/v2", "group/project/image", "group/project/image", "https://registry.gitlab.com"},
	}
	for _, c := range cases {
		rp := proxyRepo(c.remote)
		if got := upstreamImage(rp, c.image); got != c.wantImage {
			t.Errorf("upstreamImage(%s, %s) = %s, want %s", c.remote, c.image, got, c.wantImage)
		}
		if got := upstreamBase(rp); got != c.wantBase {
			t.Errorf("upstreamBase(%s) = %s, want %s", c.remote, got, c.wantBase)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, p := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`)
	if scheme != "bearer" || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" ||
		p["scope"] != "repository:library/alpine:pull" {
		t.Fatalf("got %s %v", scheme, p)
	}
	scheme, p = parseChallenge(`Bearer realm="https://gitlab.com/jwt/auth", service="container_registry", scope="repository:a/b:pull,push", error="insufficient_scope"`)
	if scheme != "bearer" || p["scope"] != "repository:a/b:pull,push" || p["error"] != "insufficient_scope" {
		t.Fatalf("got %s %v", scheme, p)
	}
	scheme, p = parseChallenge(`Basic realm="Registry"`)
	if scheme != "basic" || p["realm"] != "Registry" {
		t.Fatalf("got %s %v", scheme, p)
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{"r/alpine", "r/library/alpine", "r/a.b/c-d/e__f", "docker-hub/library/alpine"} {
		if _, _, ok := splitName(n); !ok {
			t.Errorf("%s should be valid", n)
		}
	}
	for _, n := range []string{"alpine", "r/", "r/Alpine", "r/_blobs", "r/a/_tags", "r/a//b", "/a"} {
		if _, _, ok := splitName(n); ok {
			t.Errorf("%s should be invalid", n)
		}
	}
	h := &Handler{}
	if got := h.ClientURL("https://entrepot.example.com", &repo.Repository{Repository: &store.Repository{Name: "docker-hosted"}}); got != "entrepot.example.com/docker-hosted" {
		t.Errorf("ClientURL = %s", got)
	}
	if got := h.ClientURL("http://localhost:8080/", &repo.Repository{Repository: &store.Repository{Name: "d"}}); got != "localhost:8080/d" {
		t.Errorf("ClientURL = %s", got)
	}
}

func TestValidate(t *testing.T) {
	h := &Handler{}
	for remote, ok := range map[string]bool{
		"https://registry-1.docker.io": true,
		"http://localhost:5000":        true,
		"https://ghcr.io/v2/":          true,
		"ftp://example.com":            false,
		"registry-1.docker.io":         false,
		"https://example.com/sub":      false,
	} {
		err := h.ValidateRepository(repo.KindProxy, repo.Config{Proxy: &repo.ProxyConfig{RemoteURL: remote}})
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", remote, err, ok)
		}
	}
}

func TestNextLink(t *testing.T) {
	got := nextLink("https://r.example/v2/a/tags/list?n=2", `</v2/a/tags/list?n=2&last=b>; rel="next"`)
	if got != "https://r.example/v2/a/tags/list?n=2&last=b" {
		t.Fatal(got)
	}
	if nextLink("https://r.example/x", "") != "" {
		t.Fatal("expected no next link")
	}
}
