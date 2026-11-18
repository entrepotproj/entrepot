package helm_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

// chart builds a packaged chart like `helm package` does.
func chart(t *testing.T, name, version, extra string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := []struct{ name, body string }{
		{name + "/Chart.yaml", fmt.Sprintf("apiVersion: v2\nname: %s\nversion: %s\nappVersion: 1.10\ndescription: The %s chart\ntype: application\nkeywords: [demo, test]\nmaintainers:\n  - name: Jane\n    email: jane@example.com\nannotations:\n  category: Testing\n%s", name, version, name, extra)},
		{name + "/values.yaml", "replicas: 1\n"},
		{name + "/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"},
		// A dependency's Chart.yaml must not be mistaken for the chart's.
		{name + "/charts/dep/Chart.yaml", "apiVersion: v2\nname: dep\nversion: 9.9.9\n"},
	}
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write([]byte(f.body))                                                                                //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	gz.Close() //nolint:errcheck
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func prov(file string, tgz []byte) []byte {
	return []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\napiVersion: v2\nname: x\n\n...\nfiles:\n  " +
		file + ": sha256:" + sha(tgz) + "\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n")
}

type indexFile struct {
	APIVersion string `yaml:"apiVersion"`
	Generated  string `yaml:"generated"`
	Entries    map[string][]struct {
		APIVersion  string            `yaml:"apiVersion"`
		Name        string            `yaml:"name"`
		Version     string            `yaml:"version"`
		AppVersion  string            `yaml:"appVersion"`
		Description string            `yaml:"description"`
		Type        string            `yaml:"type"`
		Keywords    []string          `yaml:"keywords"`
		Annotations map[string]string `yaml:"annotations"`
		Maintainers []struct {
			Name, Email string
		} `yaml:"maintainers"`
		URLs    []string `yaml:"urls"`
		Digest  string   `yaml:"digest"`
		Created string   `yaml:"created"`
	} `yaml:"entries"`
}

func getIndex(t *testing.T, inst *testutil.Instance, repoName, token string) indexFile {
	t.Helper()
	body := testutil.Expect(t, inst.Do("GET", "/repository/"+repoName+"/index.yaml", token, nil), http.StatusOK)
	var ix indexFile
	if err := yaml.Unmarshal([]byte(body), &ix); err != nil {
		t.Fatalf("index.yaml: %v\n%s", err, body)
	}
	if ix.APIVersion != "v1" || ix.Generated == "" {
		t.Fatalf("index header: %+v", ix)
	}
	return ix
}

func versions(ix indexFile, name string) []string {
	var out []string
	for _, e := range ix.Entries[name] {
		out = append(out, e.Version)
	}
	return out
}

func multipartBody(t *testing.T, fields map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, k := range []string{"chart", "prov", "file"} {
		if v, ok := fields[k]; ok {
			fn := "upload.tgz"
			if k == "prov" {
				fn = "demo.tgz.prov" // deliberately not the chart file name
			}
			fw, _ := mw.CreateFormFile(k, fn)
			fw.Write(v) //nolint:errcheck
		}
	}
	mw.Close() //nolint:errcheck
	return &body, mw.FormDataContentType()
}

func TestHostedHelm(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("helm-hosted", "helm", "hosted", nil)
	tok := testutil.BootstrapToken
	base := "/repository/helm-hosted/"

	v010 := chart(t, "demo", "0.1.0", "")
	v020 := chart(t, "demo", "0.2.0", "")
	rc := chart(t, "demo", "1.0.0-rc.1", "")
	other := chart(t, "other", "2.0.0", "deprecated: true\n")

	// PUT (charts/ and root), ChartMuseum raw and multipart, generic API.
	testutil.Expect(t, inst.Do("PUT", base+"charts/demo-0.1.0.tgz", tok, bytes.NewReader(v010)), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", base+"demo-0.2.0.tgz", tok, bytes.NewReader(v020)), http.StatusCreated)
	if b := testutil.Expect(t, inst.Do("POST", base+"api/charts", tok, bytes.NewReader(rc), "Content-Type", "application/octet-stream"), http.StatusCreated); !strings.Contains(b, `"saved":true`) {
		t.Fatalf("chartmuseum upload: %s", b)
	}
	body, ct := multipartBody(t, map[string][]byte{"chart": other, "prov": prov("other-2.0.0.tgz", other)})
	testutil.Expect(t, inst.Do("POST", base+"api/charts", tok, body, "Content-Type", ct), http.StatusCreated)
	testutil.Expect(t, inst.Do("POST", base+"api/prov", tok, bytes.NewReader(prov("demo-0.1.0.tgz", v010))), http.StatusCreated)
	// The multi-tenant ChartMuseum layout used by `helm cm-push`.
	body, ct = multipartBody(t, map[string][]byte{"chart": chart(t, "pushed", "0.0.1", "")})
	testutil.Expect(t, inst.Do("POST", "/api/repository/helm-hosted/charts", tok, body, "Content-Type", ct), http.StatusCreated)
	testutil.Expect(t, inst.Do("POST", "/api/repository/helm-hosted/charts", "", bytes.NewReader(v010)), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("GET", "/api/repository/helm-hosted/charts/pushed", tok, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("DELETE", "/api/repository/helm-hosted/charts/pushed/0.0.1", tok, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/api/repository/nope/charts", tok, nil), http.StatusNotFound)

	// Authorisation, kinds and validation.
	testutil.Expect(t, inst.Do("GET", base+"index.yaml", "", nil), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("PUT", base+"charts/demo-0.3.0.tgz", "", bytes.NewReader(v010)), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("PUT", base+"charts/bad.tgz", tok, strings.NewReader("not a chart")), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("POST", base+"api/charts", tok, bytes.NewReader(chart(t, "demo", "not-semver", ""))), http.StatusBadRequest)
	// Redeploying different content is refused (identical content is fine).
	testutil.Expect(t, inst.Do("PUT", base+"charts/demo-0.1.0.tgz", tok, bytes.NewReader(v010)), http.StatusCreated)
	testutil.Expect(t, inst.Do("POST", base+"api/charts", tok, bytes.NewReader(chart(t, "demo", "0.1.0", "home: https://x\n"))), http.StatusConflict)

	ix := getIndex(t, inst, "helm-hosted", tok)
	if got := strings.Join(versions(ix, "demo"), ","); got != "1.0.0-rc.1,0.2.0,0.1.0" {
		t.Fatalf("demo versions %s", got)
	}
	e := ix.Entries["demo"][2]
	if e.APIVersion != "v2" || e.Name != "demo" || e.AppVersion != "1.10" || e.Description != "The demo chart" || e.Type != "application" ||
		len(e.Keywords) != 2 || e.Annotations["category"] != "Testing" || len(e.Maintainers) != 1 || e.Maintainers[0].Email != "jane@example.com" ||
		len(e.URLs) != 1 || e.URLs[0] != "charts/demo-0.1.0.tgz" || e.Digest != sha(v010) || e.Created == "" {
		t.Fatalf("index entry: %+v", e)
	}
	if len(ix.Entries["other"]) != 1 {
		t.Fatalf("other: %+v", ix.Entries)
	}
	raw := testutil.Expect(t, inst.Do("GET", base+"index.yaml", tok, nil), http.StatusOK)
	if !strings.Contains(raw, "deprecated: true") || strings.Contains(raw, "9.9.9") {
		t.Fatalf("index.yaml:\n%s", raw)
	}
	// Conditional requests.
	resp := inst.Do("GET", base+"index.yaml", tok, nil)
	etag := resp.Header.Get("ETag")
	testutil.Body(resp)
	testutil.Expect(t, inst.Do("GET", base+"index.yaml", tok, nil, "If-None-Match", etag), http.StatusNotModified)

	// Downloads.
	if got := testutil.Expect(t, inst.Do("GET", base+"charts/demo-0.1.0.tgz", tok, nil), http.StatusOK); got != string(v010) {
		t.Fatal("download differs")
	}
	if got := testutil.Expect(t, inst.Do("GET", base+"demo-0.2.0.tgz", tok, nil), http.StatusOK); got != string(v020) {
		t.Fatal("root download differs")
	}
	if got := testutil.Expect(t, inst.Do("GET", base+"charts/demo-0.1.0.tgz.prov", tok, nil), http.StatusOK); !strings.Contains(got, "PGP SIGNED") {
		t.Fatalf("prov: %s", got)
	}
	testutil.Expect(t, inst.Do("GET", base+"charts/other-2.0.0.tgz.prov", tok, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", base+"charts/demo-9.9.9.tgz", tok, nil), http.StatusNotFound)

	// ChartMuseum listing.
	var all map[string][]map[string]any
	if err := json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", base+"api/charts", tok, nil), http.StatusOK)), &all); err != nil || len(all["demo"]) != 3 {
		t.Fatalf("api/charts: %v %+v", err, all)
	}
	var latest map[string]any
	json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", base+"api/charts/demo/latest", tok, nil), http.StatusOK)), &latest) //nolint:errcheck
	if latest["version"] != "1.0.0-rc.1" {
		t.Fatalf("latest: %+v", latest)
	}
	testutil.Expect(t, inst.Do("GET", base+"api/charts/nope", tok, nil), http.StatusNotFound)

	// Components carry the chart metadata.
	var comps []struct {
		Name, Version string
		Attrs         map[string]any
	}
	inst.JSON("GET", "/repositories/helm-hosted/components", nil, http.StatusOK, &comps)
	if len(comps) != 4 {
		t.Fatalf("components: %+v", comps)
	}

	// ChartMuseum delete removes the version and its provenance file.
	testutil.Expect(t, inst.Do("DELETE", base+"api/charts/demo/0.1.0", tok, nil), http.StatusOK)
	if got := strings.Join(versions(getIndex(t, inst, "helm-hosted", tok), "demo"), ","); got != "1.0.0-rc.1,0.2.0" {
		t.Fatalf("after delete: %s", got)
	}
	testutil.Expect(t, inst.Do("GET", base+"charts/demo-0.1.0.tgz.prov", tok, nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("DELETE", base+"api/charts/demo/0.1.0", tok, nil), http.StatusNotFound)

	// Deleting the package asset through the management API: the index
	// follows and the orphaned provenance file goes too (DeleteHook).
	var assets struct {
		Items []struct{ ID, Path string } `json:"items"`
	}
	inst.JSON("GET", "/repositories/helm-hosted/assets?prefix=charts/other", nil, http.StatusOK, &assets)
	for _, a := range assets.Items {
		if a.Path == "charts/other-2.0.0.tgz" {
			inst.JSON("DELETE", "/assets/"+a.ID, nil, http.StatusNoContent, nil)
		}
	}
	if ix := getIndex(t, inst, "helm-hosted", tok); len(ix.Entries["other"]) != 0 {
		t.Fatalf("other still listed: %+v", ix.Entries["other"])
	}
	testutil.Expect(t, inst.Do("GET", base+"charts/other-2.0.0.tgz.prov", tok, nil), http.StatusNotFound)

	// Generic upload API.
	body, ct = multipartBody(t, map[string][]byte{"file": chart(t, "uploaded", "3.1.4", "")})
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/helm-hosted/upload", tok, body, "Content-Type", ct), http.StatusCreated)
	if v := versions(getIndex(t, inst, "helm-hosted", tok), "uploaded"); len(v) != 1 || v[0] != "3.1.4" {
		t.Fatalf("uploaded: %v", v)
	}
	// Plain DELETE of a package path.
	testutil.Expect(t, inst.Do("DELETE", base+"charts/uploaded-3.1.4.tgz", tok, nil), http.StatusNoContent)
	if v := versions(getIndex(t, inst, "helm-hosted", tok), "uploaded"); len(v) != 0 {
		t.Fatalf("uploaded after delete: %v", v)
	}
}

func TestProxyAndGroupHelm(t *testing.T) {
	foo := chart(t, "foo", "1.0.0", "")
	foo2 := chart(t, "foo", "1.1.0", "")
	bar := chart(t, "bar", "0.5.0", "")
	secret := chart(t, "acme-secret", "1.0.0", "")
	var indexHits, fooHits, releaseHits atomic.Int32
	// Charts hosted on another host (like GitHub releases).
	releases := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/bar-0.5.0.tgz":
			releaseHits.Add(1)
			w.Write(bar) //nolint:errcheck
		case "/download/bar-0.5.0.tgz.prov":
			w.Write(prov("bar-0.5.0.tgz", bar)) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer releases.Close()
	upstreamIndex := fmt.Sprintf(`apiVersion: v1
entries:
  foo:
  - apiVersion: v2
    name: foo
    version: 1.1.0
    appVersion: 2.10
    urls: [charts/foo-1.1.0.tgz]
    digest: %s
    created: "2024-01-02T00:00:00Z"
  - apiVersion: v2
    name: foo
    version: 1.0.0
    urls: [/sub/charts/foo-1.0.0.tgz]
    digest: %s
    created: "2024-01-01T00:00:00Z"
  bar:
  - apiVersion: v2
    name: bar
    version: 0.5.0
    description: Bar
    urls: [%s/download/bar-0.5.0.tgz]
    digest: %s
  broken:
  - apiVersion: v2
    name: broken
    version: 0.0.1
    urls: [charts/broken-0.0.1.tgz]
    digest: %s
  acme-secret:
  - apiVersion: v2
    name: acme-secret
    version: 1.0.0
    urls: [charts/acme-secret-1.0.0.tgz]
generated: "2024-01-03T00:00:00Z"
`, sha(foo2), sha(foo), releases.URL, sha(bar), sha([]byte("the real thing")))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sub/index.yaml":
			indexHits.Add(1)
			w.Header().Set("ETag", `"ix1"`)
			if r.Header.Get("If-None-Match") == `"ix1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Write([]byte(upstreamIndex)) //nolint:errcheck
		case "/sub/charts/foo-1.1.0.tgz":
			fooHits.Add(1)
			w.Write(foo2) //nolint:errcheck
		case "/sub/charts/foo-1.0.0.tgz":
			w.Write(foo) //nolint:errcheck
		case "/sub/charts/broken-0.0.1.tgz":
			w.Write([]byte("corrupt")) //nolint:errcheck
		case "/sub/charts/acme-secret-1.0.0.tgz":
			w.Write(secret) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("helm-remote", "helm", "proxy", map[string]any{
		"anonymousRead": true, "proxy": map[string]any{"remoteUrl": upstream.URL + "/sub"},
	})
	base := "/repository/helm-remote/"
	for i := 0; i < 2; i++ {
		ix := getIndex(t, inst, "helm-remote", "")
		if got := strings.Join(versions(ix, "foo"), ","); got != "1.1.0,1.0.0" {
			t.Fatalf("proxy foo versions %s", got)
		}
		if e := ix.Entries["foo"][0]; e.URLs[0] != "charts/foo-1.1.0.tgz" || e.AppVersion != "2.10" || e.Digest != sha(foo2) || e.Created != "2024-01-02T00:00:00Z" {
			t.Fatalf("proxy entry: %+v", e)
		}
		if e := ix.Entries["bar"][0]; e.URLs[0] != "charts/bar-0.5.0.tgz" || e.Description != "Bar" {
			t.Fatalf("proxy bar: %+v", e)
		}
	}
	if indexHits.Load() != 1 {
		t.Fatalf("index fetched %d times", indexHits.Load())
	}
	raw := testutil.Expect(t, inst.Do("GET", base+"index.yaml", "", nil), http.StatusOK)
	if strings.Contains(raw, upstream.URL) || strings.Contains(raw, releases.URL) {
		t.Fatalf("upstream URLs leak into the index:\n%s", raw)
	}
	for i := 0; i < 3; i++ {
		if got := testutil.Expect(t, inst.Do("GET", base+"charts/foo-1.1.0.tgz", "", nil), http.StatusOK); got != string(foo2) {
			t.Fatal("proxied chart differs")
		}
	}
	if fooHits.Load() != 1 {
		t.Fatalf("chart fetched %d times", fooHits.Load())
	}
	// Index-relative (absolute path) and cross-host URLs.
	if got := testutil.Expect(t, inst.Do("GET", base+"charts/foo-1.0.0.tgz", "", nil), http.StatusOK); got != string(foo) {
		t.Fatal("foo 1.0.0 differs")
	}
	if got := testutil.Expect(t, inst.Do("GET", base+"charts/bar-0.5.0.tgz", "", nil), http.StatusOK); got != string(bar) {
		t.Fatal("cross-host chart differs")
	}
	testutil.Expect(t, inst.Do("GET", base+"charts/bar-0.5.0.tgz.prov", "", nil), http.StatusOK)
	// Digest mismatch: rejected, not cached.
	resp := inst.Do("GET", base+"charts/broken-0.0.1.tgz", "", nil)
	if resp.StatusCode < 500 {
		t.Fatalf("corrupt chart served with %d", resp.StatusCode)
	}
	testutil.Body(resp)
	testutil.Expect(t, inst.Do("GET", base+"charts/nope-1.0.0.tgz", "", nil), http.StatusNotFound)
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/repositories/helm-remote/components", nil, http.StatusOK, &comps)
	if len(comps) != 3 {
		t.Fatalf("proxy components: %+v", comps)
	}
	testutil.Expect(t, inst.Do("PUT", base+"charts/foo-9.0.0.tgz", testutil.BootstrapToken, bytes.NewReader(foo)), http.StatusMethodNotAllowed)

	// Routing rule: blocked charts vanish from the index and cannot be fetched.
	inst.JSON("POST", "/routing-rules", map[string]any{"name": "no-acme", "mode": "block", "matchers": []string{"^acme-"}}, http.StatusCreated, nil)
	inst.CreateRepo("helm-routed", "helm", "proxy", map[string]any{
		"anonymousRead": true, "proxy": map[string]any{"remoteUrl": upstream.URL + "/sub", "routingRule": "no-acme"},
	})
	rix := getIndex(t, inst, "helm-routed", "")
	if len(rix.Entries["acme-secret"]) != 0 || len(rix.Entries["foo"]) != 2 {
		t.Fatalf("routed index: %+v", rix.Entries)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/helm-routed/charts/acme-secret-1.0.0.tgz", "", nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/helm-routed/charts/foo-1.0.0.tgz", "", nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", base+"charts/acme-secret-1.0.0.tgz", "", nil), http.StatusOK)

	// Groups.
	inst.CreateRepo("helm-local", "helm", "hosted", nil)
	mine := chart(t, "foo", "9.0.0", "")
	testutil.Expect(t, inst.Do("PUT", "/repository/helm-local/charts/foo-9.0.0.tgz", testutil.BootstrapToken, bytes.NewReader(mine)), http.StatusCreated)
	internal := chart(t, "internal", "0.1.0", "")
	testutil.Expect(t, inst.Do("PUT", "/repository/helm-local/charts/internal-0.1.0.tgz", testutil.BootstrapToken, bytes.NewReader(internal)), http.StatusCreated)
	inst.CreateRepo("helm-merged", "helm", "group", map[string]any{
		"anonymousRead": true, "group": map[string]any{"members": []string{"helm-local", "helm-remote"}, "preferHosted": false},
	})
	inst.CreateRepo("helm-all", "helm", "group", map[string]any{
		"anonymousRead": true, "group": map[string]any{"members": []string{"helm-remote", "helm-local"}},
	})
	mix := getIndex(t, inst, "helm-merged", "")
	if got := strings.Join(versions(mix, "foo"), ","); got != "9.0.0,1.1.0,1.0.0" {
		t.Fatalf("merged foo: %s", got)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/helm-merged/charts/foo-1.1.0.tgz", "", nil), http.StatusOK); got != string(foo2) {
		t.Fatal("merged proxied chart differs")
	}
	// preferHosted (default): foo is published internally, so the public
	// versions are not merged in; other public charts still are.
	gix := getIndex(t, inst, "helm-all", "")
	if got := strings.Join(versions(gix, "foo"), ","); got != "9.0.0" {
		t.Fatalf("preferHosted foo: %s", got)
	}
	if len(gix.Entries["bar"]) != 1 || len(gix.Entries["internal"]) != 1 || gix.Entries["foo"][0].URLs[0] != "charts/foo-9.0.0.tgz" {
		t.Fatalf("group index: %+v", gix.Entries)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/helm-all/charts/foo-9.0.0.tgz", "", nil), http.StatusOK); got != string(mine) {
		t.Fatal("group hosted chart differs")
	}
	testutil.Expect(t, inst.Do("GET", "/repository/helm-all/charts/foo-1.1.0.tgz", "", nil), http.StatusNotFound)
	if got := testutil.Expect(t, inst.Do("GET", "/repository/helm-all/charts/bar-0.5.0.tgz", "", nil), http.StatusOK); got != string(bar) {
		t.Fatal("group proxied chart differs")
	}
	if releaseHits.Load() != 1 {
		t.Fatalf("release fetched %d times (group should reuse the proxy cache)", releaseHits.Load())
	}
	testutil.Expect(t, inst.Do("PUT", "/repository/helm-all/charts/foo-9.0.1.tgz", testutil.BootstrapToken, bytes.NewReader(mine)), http.StatusMethodNotAllowed)
	// Group index follows member changes.
	testutil.Expect(t, inst.Do("DELETE", "/repository/helm-local/api/charts/internal/0.1.0", testutil.BootstrapToken, nil), http.StatusOK)
	if gix := getIndex(t, inst, "helm-all", ""); len(gix.Entries["internal"]) != 0 {
		t.Fatalf("deleted chart still in group index: %+v", gix.Entries["internal"])
	}
}
