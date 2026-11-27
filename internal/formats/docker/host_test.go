package docker_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/entrepotproj/entrepot/internal/testutil"
)

// hostTransport sends requests for any hostname to the test server, so
// repository hostnames work without DNS.
func hostTransport(inst *testutil.Instance) *http.Transport {
	addr := host(inst)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return tr
}

// onHost is hostname:port of the test server under another name.
func onHost(inst *testutil.Instance, hostname string) string {
	_, port, _ := net.SplitHostPort(host(inst))
	return hostname + ":" + port
}

func hostRef(t *testing.T, inst *testutil.Instance, hostname, s string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(onHost(inst, hostname)+"/"+s, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// hostDo sends a request to hostname (on the test server).
func hostDo(t *testing.T, inst *testutil.Instance, method, hostname, path string, setup func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+onHost(inst, hostname)+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(req)
	}
	resp, err := (&http.Client{Transport: hostTransport(inst),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func bearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

// A Docker repository with docker.host is its own registry on that host:
// images have no repository prefix, and the path form keeps working.
func TestRepositoryHost(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("team", "docker", "hosted", map[string]any{"docker": map[string]any{"host": "Team.Test"}})
	inst.CreateRepo("other", "docker", "hosted", nil)
	tr := remote.WithTransport(hostTransport(inst))

	var rp struct {
		URL    string `json:"url"`
		Docker struct {
			Host string `json:"host"`
		} `json:"docker"`
	}
	inst.JSON("GET", "/repositories/team", nil, http.StatusOK, &rp)
	if rp.Docker.Host != "team.test" || rp.URL != "team.test" {
		t.Fatalf("repository: %+v", rp)
	}

	// Push and pull on the hostname; the same image by path.
	img, _ := random.Image(512, 2)
	dg, _ := img.Digest()
	if err := remote.Write(hostRef(t, inst, "team.test", "app:v1"), img, basic(testutil.BootstrapToken), tr); err != nil {
		t.Fatalf("push on host: %v", err)
	}
	if err := remote.Write(hostRef(t, inst, "team.test", "app:v2"), img, basic(testutil.BootstrapToken), tr); err != nil {
		t.Fatalf("push v2: %v", err)
	}
	got, err := remote.Image(hostRef(t, inst, "team.test", "app:v1"), basic(testutil.BootstrapToken), tr)
	if err != nil {
		t.Fatalf("pull on host: %v", err)
	}
	pullAll(t, got)
	byPath, err := remote.Image(ref(t, inst, "team/app:v1"), basic(testutil.BootstrapToken))
	if err != nil {
		t.Fatalf("pull by path: %v", err)
	}
	if d, _ := byPath.Digest(); d != dg {
		t.Fatalf("digest by path %s, want %s", d, dg)
	}

	// Anonymous: the challenge's realm is on the hostname, the scope names
	// the image.
	resp := hostDo(t, inst, "GET", "team.test", "/v2/app/manifests/v1", nil)
	resp.Body.Close()
	want := `Bearer realm="http://` + onHost(inst, "team.test") + `/v2/token",service="entrepot",scope="repository:app:pull"`
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != want {
		t.Fatalf("challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// Tags, pagination and the catalog leave out the repository.
	resp = hostDo(t, inst, "GET", "team.test", "/v2/app/tags/list?n=1", bearer(testutil.BootstrapToken))
	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tags)
	resp.Body.Close()
	if tags.Name != "app" || len(tags.Tags) != 1 || resp.Header.Get("Link") != `</v2/app/tags/list?n=1&last=v1>; rel="next"` {
		t.Fatalf("tags: %+v %q", tags, resp.Header.Get("Link"))
	}
	resp = hostDo(t, inst, "GET", "team.test", "/v2/_catalog", bearer(testutil.BootstrapToken))
	var cat struct {
		Repositories []string `json:"repositories"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cat)
	resp.Body.Close()
	if len(cat.Repositories) != 1 || cat.Repositories[0] != "app" {
		t.Fatalf("catalog on host: %+v", cat)
	}
	mainCat := testutil.Expect(t, inst.Do("GET", "/v2/_catalog", testutil.BootstrapToken, nil), http.StatusOK)
	if !strings.Contains(mainCat, `"team/app"`) {
		t.Fatalf("catalog on the main host: %s", mainCat)
	}

	// Upload and mount locations leave out the repository; from names an
	// image of the same repository.
	resp = hostDo(t, inst, "POST", "team.test", "/v2/app/blobs/uploads/", bearer(testutil.BootstrapToken))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || !strings.HasPrefix(resp.Header.Get("Location"), "/v2/app/blobs/uploads/") {
		t.Fatalf("upload: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	layers, _ := img.Layers()
	ld, _ := layers[0].Digest()
	resp = hostDo(t, inst, "POST", "team.test", "/v2/copy/blobs/uploads/?mount="+ld.String()+"&from=app", bearer(testutil.BootstrapToken))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Location") != "/v2/copy/blobs/"+ld.String() {
		t.Fatalf("mount: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The token endpoint on the hostname grants the image scope.
	resp = hostDo(t, inst, "GET", "team.test", "/v2/token?service=entrepot&scope=repository:app:pull,push", func(r *http.Request) {
		r.SetBasicAuth("docker", testutil.BootstrapToken)
	})
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	parts := strings.Split(tok.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("token: %q", tok.Token)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(payload), `"name":"app","actions":["pull","push"]`) {
		t.Fatalf("token access: %s", payload)
	}

	// A host that belongs to no repository behaves as the main host.
	resp = hostDo(t, inst, "GET", "unknown.test", "/v2/team/app/tags/list", bearer(testutil.BootstrapToken))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unknown host: %d", resp.StatusCode)
	}

	// Requests on the hostname count towards the repository's usage.
	if err := inst.App.Usage.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var requests int64
	if err := inst.App.Pool.QueryRow(context.Background(), `SELECT coalesce(sum(u.requests), 0) FROM usage_minute u
		JOIN repositories r ON r.id = u.repository_id WHERE r.name = 'team'`).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if requests < 8 {
		t.Fatalf("usage requests for team: %d", requests)
	}

	// Removing the hostname: the repository is addressed by path again.
	var cleared map[string]any
	inst.JSON("PUT", "/repositories/team", map[string]any{"name": "team", "format": "docker", "kind": "hosted",
		"blobStore": "default"}, http.StatusOK, &cleared)
	if _, ok := cleared["docker"]; ok || cleared["url"] != host(inst)+"/team" {
		t.Fatalf("after removing the host: %+v", cleared)
	}
	resp = hostDo(t, inst, "GET", "team.test", "/v2/app/tags/list", bearer(testutil.BootstrapToken))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("old host still mapped: %d", resp.StatusCode)
	}
}

// A Docker Hub proxy on its own hostname works as Docker Engine's registry
// mirror: anonymous pulls without the repository prefix, even when the
// daemon sends Docker Hub credentials.
func TestRepositoryHostMirror(t *testing.T) {
	up := newFakeUpstream(t, "", "")
	img, _ := random.Image(1024, 2)
	dg, _ := img.Digest()
	up.push(t, "library/alpine:3.20", img)

	inst := testutil.New(t)
	inst.CreateRepo("hub", "docker", "proxy", map[string]any{"anonymousRead": true,
		"proxy": map[string]any{"remoteUrl": up.srv.URL}, "docker": map[string]any{"host": "mirror.test"}})
	tr := remote.WithTransport(hostTransport(inst))

	for _, auth := range []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithAuth(&authn.Basic{Username: "dockerhub-user", Password: "dockerhub-password"}),
	} {
		got, err := remote.Image(hostRef(t, inst, "mirror.test", "library/alpine:3.20"), auth, tr)
		if err != nil {
			t.Fatalf("mirror pull: %v", err)
		}
		if d, _ := got.Digest(); d != dg {
			t.Fatalf("digest %s, want %s", d, dg)
		}
		pullAll(t, got)
	}

	// Without anonymous read, invalid credentials are refused.
	inst.CreateRepo("private-hub", "docker", "proxy", map[string]any{
		"proxy": map[string]any{"remoteUrl": up.srv.URL}, "docker": map[string]any{"host": "private.test"}})
	resp := hostDo(t, inst, "GET", "private.test", "/v2/token?scope=repository:library/alpine:pull", func(r *http.Request) {
		r.SetBasicAuth("dockerhub-user", "dockerhub-password")
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid credentials on a private mirror: %d", resp.StatusCode)
	}
}

func TestRepositoryHostValidation(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("one", "docker", "hosted", map[string]any{"docker": map[string]any{"host": "one.test"}})
	create := func(name, format string, host string, want int) {
		t.Helper()
		inst.JSON("POST", "/repositories", map[string]any{"name": name, "format": format, "kind": "hosted",
			"blobStore": "default", "docker": map[string]any{"host": host}}, want, nil)
	}
	create("two", "docker", "ONE.test", http.StatusConflict)
	for _, bad := range []string{"https://two.test", "two.test:5000", "two.test/path", "10.0.0.1", "-two.test", "two_.test", "a..b"} {
		create("two", "docker", bad, http.StatusBadRequest)
	}
	create("npm-two", "npm", "npm.test", http.StatusBadRequest)
	create("two", "docker", "two.test", http.StatusCreated)
	// Updating a repository keeps its own host.
	inst.JSON("PUT", "/repositories/one", map[string]any{"name": "one", "format": "docker", "kind": "hosted",
		"blobStore": "default", "docker": map[string]any{"host": "one.test"}}, http.StatusOK, nil)
}
