package pypi_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func metadataDoc(name, version, requires string) string {
	return fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: The %s package\nRequires-Python: %s\nAuthor: Jane\nLicense: MIT\n\nLong description of %s.\n", name, version, name, requires, name)
}

// wheel builds a minimal wheel archive.
func wheel(t *testing.T, name, version, requires string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dist := strings.ReplaceAll(name, "-", "_") + "-" + version
	files := map[string]string{
		strings.ReplaceAll(name, "-", "_") + "/__init__.py": "x = 1\n",
		dist + ".dist-info/METADATA":                        metadataDoc(name, version, requires),
		dist + ".dist-info/WHEEL":                           "Wheel-Version: 1.0\n",
	}
	for n, c := range files {
		f, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(c)) //nolint:errcheck
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), dist + "-py3-none-any.whl"
}

// sdist builds a minimal .tar.gz source distribution.
func sdist(t *testing.T, name, version string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dir := name + "-" + version
	for n, c := range map[string]string{dir + "/PKG-INFO": metadataDoc(name, version, ">=3.9"), dir + "/setup.py": "pass\n"} {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write([]byte(c))                                                                           //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	gz.Close() //nolint:errcheck
	return buf.Bytes(), dir + ".tar.gz"
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// twineUpload posts a file like `twine upload` does (basic auth, legacy API).
func twineUpload(t *testing.T, inst *testutil.Instance, repoName, token string, fields map[string]string, filename string, content []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField(":action", "file_upload")  //nolint:errcheck
	mw.WriteField("protocol_version", "1")   //nolint:errcheck
	mw.WriteField("metadata_version", "2.1") //nolint:errcheck
	mw.WriteField("filetype", "bdist_wheel") //nolint:errcheck
	for k, v := range fields {
		mw.WriteField(k, v) //nolint:errcheck
	}
	fw, _ := mw.CreateFormFile("content", filename)
	fw.Write(content) //nolint:errcheck
	mw.Close()        //nolint:errcheck
	req, _ := http.NewRequest("POST", inst.URL+"/repository/"+repoName+"/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.SetBasicAuth("__token__", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func apiUpload(t *testing.T, inst *testutil.Instance, repoName, filename string, content []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", filename)
	fw.Write(content) //nolint:errcheck
	mw.Close()        //nolint:errcheck
	return inst.Do("POST", "/api/v1/repositories/"+repoName+"/upload", testutil.BootstrapToken, &body, "Content-Type", mw.FormDataContentType())
}

type simpleJSON struct {
	Meta  map[string]string `json:"meta"`
	Name  string            `json:"name"`
	Files []struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython string            `json:"requires-python"`
		CoreMetadata   any               `json:"core-metadata"`
		Size           int64             `json:"size"`
	} `json:"files"`
	Versions []string `json:"versions"`
}

func getJSON(t *testing.T, inst *testutil.Instance, path, token string) simpleJSON {
	t.Helper()
	resp := inst.Do("GET", path, token, nil, "Accept", "application/vnd.pypi.simple.v1+json, text/html;q=0.01")
	if ct := resp.Header.Get("Content-Type"); ct != "application/vnd.pypi.simple.v1+json" {
		t.Fatalf("content type %q", ct)
	}
	var out simpleJSON
	if err := json.Unmarshal([]byte(testutil.Expect(t, resp, http.StatusOK)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// resolve resolves a (relative) link from a page URL to a server path.
func resolve(t *testing.T, page, link string) string {
	t.Helper()
	base, _ := url.Parse("http://x" + page)
	u, err := base.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.EscapedPath()
}

func TestHostedPyPI(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("py", "pypi", "hosted", nil)
	writer := inst.Token("ci", "developer", "py")
	reader := inst.Token("viewer", "viewer", "*")

	whl, whlName := wheel(t, "my-pkg", "1.0.0", ">=3.8")
	fields := map[string]string{"name": "my-pkg", "version": "1.0.0", "sha256_digest": sha(whl)}

	testutil.Expect(t, twineUpload(t, inst, "py", "", fields, whlName, whl), http.StatusUnauthorized)
	testutil.Expect(t, twineUpload(t, inst, "py", reader, fields, whlName, whl), http.StatusForbidden)
	bad := map[string]string{"name": "my-pkg", "version": "1.0.0", "sha256_digest": strings.Repeat("0", 64)}
	testutil.Expect(t, twineUpload(t, inst, "py", writer, bad, whlName, whl), http.StatusBadRequest)
	// Filename must match the project.
	testutil.Expect(t, twineUpload(t, inst, "py", writer, map[string]string{"name": "other", "version": "1.0.0"}, whlName, whl), http.StatusBadRequest)
	testutil.Expect(t, twineUpload(t, inst, "py", writer, fields, whlName, whl), http.StatusOK)
	// Same content again is idempotent; different content is a redeploy.
	testutil.Expect(t, twineUpload(t, inst, "py", writer, fields, whlName, whl), http.StatusOK)
	whl2, _ := wheel(t, "my-pkg", "1.0.0", ">=3.9")
	testutil.Expect(t, twineUpload(t, inst, "py", writer, map[string]string{"name": "my-pkg", "version": "1.0.0"}, whlName, whl2), http.StatusConflict)

	sd, sdName := sdist(t, "my-pkg", "1.0.0")
	testutil.Expect(t, twineUpload(t, inst, "py", writer, map[string]string{"name": "my-pkg", "version": "1.0.0", "requires_python": ">=3.8"}, sdName, sd), http.StatusOK)

	// Project index.
	idx := testutil.Expect(t, inst.Do("GET", "/repository/py/simple/", reader, nil), http.StatusOK)
	if !strings.Contains(idx, `<a href="my-pkg/">my-pkg</a>`) {
		t.Fatalf("index: %s", idx)
	}
	// Non-normalised names redirect.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", inst.URL+"/repository/py/simple/My_Pkg/", nil)
	req.Header.Set("Authorization", "Bearer "+reader)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Expect(t, resp, http.StatusMovedPermanently)
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "/repository/py/simple/my-pkg/") {
		t.Fatalf("redirect to %q", loc)
	}

	// HTML project page.
	page := testutil.Expect(t, inst.Do("GET", "/repository/py/simple/my-pkg/", reader, nil), http.StatusOK)
	wantHref := `href="../../packages/my-pkg/1.0.0/` + whlName + `#sha256=` + sha(whl) + `"`
	if !strings.Contains(page, wantHref) || !strings.Contains(page, `data-requires-python="&gt;=3.8"`) || !strings.Contains(page, `data-core-metadata="sha256=`) {
		t.Fatalf("project page:\n%s", page)
	}
	if !strings.Contains(page, sdName) {
		t.Fatalf("sdist missing:\n%s", page)
	}

	// JSON project page.
	js := getJSON(t, inst, "/repository/py/simple/my-pkg/", reader)
	if js.Meta["api-version"] == "" || js.Name != "my-pkg" || len(js.Files) != 2 || len(js.Versions) != 1 || js.Versions[0] != "1.0.0" {
		t.Fatalf("json page: %+v", js)
	}
	var whlURL, metaSHA string
	for _, f := range js.Files {
		if f.Filename == whlName {
			whlURL = f.URL
			if f.Hashes["sha256"] != sha(whl) || f.Size != int64(len(whl)) || f.RequiresPython != ">=3.8" {
				t.Fatalf("wheel entry: %+v", f)
			}
			m, _ := f.CoreMetadata.(map[string]any)
			metaSHA, _ = m["sha256"].(string)
		}
	}
	filePath := resolve(t, "/repository/py/simple/my-pkg/", whlURL)
	if got := testutil.Expect(t, inst.Do("GET", filePath, reader, nil), http.StatusOK); got != string(whl) {
		t.Fatal("downloaded wheel differs")
	}
	md := testutil.Expect(t, inst.Do("GET", filePath+".metadata", reader, nil), http.StatusOK)
	if sha([]byte(md)) != metaSHA || !strings.Contains(md, "Name: my-pkg") {
		t.Fatalf("metadata %q (sha %s want %s)", md, sha([]byte(md)), metaSHA)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/py/simple/nope/", reader, nil), http.StatusNotFound)

	// Component recorded with metadata.
	var comps []struct {
		Name    string         `json:"name"`
		Version string         `json:"version"`
		Attrs   map[string]any `json:"attrs"`
	}
	inst.JSON("GET", "/repositories/py/components", nil, http.StatusOK, &comps)
	if len(comps) != 1 || comps[0].Name != "my-pkg" || comps[0].Version != "1.0.0" || comps[0].Attrs["summary"] != "The my-pkg package" || comps[0].Attrs["requires_python"] != ">=3.8" {
		t.Fatalf("components: %+v", comps)
	}

	// Generic API upload derives name/version from the file.
	whl3, whl3Name := wheel(t, "Other.Pkg", "2.0", ">=3.10")
	testutil.Expect(t, apiUpload(t, inst, "py", whl3Name, whl3), http.StatusCreated)
	testutil.Expect(t, apiUpload(t, inst, "py", "notapackage.txt", []byte("x")), http.StatusBadRequest)
	js = getJSON(t, inst, "/repository/py/simple/other-pkg/", reader)
	if len(js.Files) != 1 || js.Files[0].RequiresPython != ">=3.10" || js.Versions[0] != "2.0" {
		t.Fatalf("api uploaded page: %+v", js)
	}
	sd2, sd2Name := sdist(t, "python-dateutil", "2.8.2")
	testutil.Expect(t, apiUpload(t, inst, "py", sd2Name, sd2), http.StatusCreated)
	js = getJSON(t, inst, "/repository/py/simple/python-dateutil/", reader)
	if len(js.Versions) != 1 || js.Versions[0] != "2.8.2" {
		t.Fatalf("sdist versions: %+v", js)
	}
	rootJS := getJSON(t, inst, "/repository/py/simple/", reader)
	_ = rootJS

	// Delete requires delete permission.
	testutil.Expect(t, inst.Do("DELETE", filePath, writer, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", filePath, testutil.BootstrapToken, nil), http.StatusNoContent)
	testutil.Expect(t, inst.Do("GET", filePath+".metadata", reader, nil), http.StatusNotFound)
	page = testutil.Expect(t, inst.Do("GET", "/repository/py/simple/my-pkg/", reader, nil), http.StatusOK)
	if strings.Contains(page, whlName) || !strings.Contains(page, sdName) {
		t.Fatalf("after delete:\n%s", page)
	}
	testutil.Expect(t, inst.Do("DELETE", "/repository/py/packages/my-pkg/", testutil.BootstrapToken, nil), http.StatusNoContent)
	testutil.Expect(t, inst.Do("GET", "/repository/py/simple/my-pkg/", reader, nil), http.StatusNotFound)
}

func TestHostedPyPIRedeploy(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("py", "pypi", "hosted", map[string]any{"hosted": map[string]any{"allowRedeploy": true}})
	whl, name := wheel(t, "pkg", "1.0", "")
	whl2, _ := wheel(t, "pkg", "1.0", ">=3")
	testutil.Expect(t, twineUpload(t, inst, "py", testutil.BootstrapToken, map[string]string{"name": "pkg", "version": "1.0"}, name, whl), http.StatusOK)
	testutil.Expect(t, twineUpload(t, inst, "py", testutil.BootstrapToken, map[string]string{"name": "pkg", "version": "1.0"}, name, whl2), http.StatusOK)
	got := testutil.Expect(t, inst.Do("GET", "/repository/py/packages/pkg/1.0/"+name, testutil.BootstrapToken, nil), http.StatusOK)
	if got != string(whl2) {
		t.Fatal("redeploy did not replace the file")
	}
}

func TestProxyAndGroupPyPI(t *testing.T) {
	demoWhl, demoName := wheel(t, "demo", "1.0", ">=3.7")
	demoMeta := metadataDoc("demo", "1.0", ">=3.7")
	corrupt := []byte("not the published content")
	legacyTar, legacyName := sdist(t, "legacy-proj", "0.5")
	var indexHits, fileHits atomic.Int32
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/demo/":
			indexHits.Add(1)
			if !strings.Contains(r.Header.Get("Accept"), "application/vnd.pypi.simple.v1+json") {
				t.Errorf("upstream Accept %q", r.Header.Get("Accept"))
			}
			w.Header().Set("ETag", `"idx1"`)
			if r.Header.Get("If-None-Match") == `"idx1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"meta": map[string]string{"api-version": "1.1"},
				"name": "demo",
				"files": []map[string]any{
					{"filename": demoName, "url": upstream.URL + "/files/aa/bb/" + demoName, "hashes": map[string]string{"sha256": sha(demoWhl)},
						"requires-python": ">=3.7", "core-metadata": map[string]string{"sha256": sha([]byte(demoMeta))}, "size": len(demoWhl)},
					{"filename": "demo-0.9.tar.gz", "url": "../../files/cc/demo-0.9.tar.gz", "hashes": map[string]string{"sha256": sha([]byte("x"))}, "yanked": "broken"},
					{"filename": "demo-0.8.tar.gz", "url": "/files/dd/demo-0.8.tar.gz", "hashes": map[string]string{"sha256": sha([]byte("other"))}},
				},
				"versions": []string{"0.8", "0.9", "1.0"},
			})
		case "/simple/legacy-proj/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Links</h1>
<a href="/files/ee/%s#sha256=%s" data-requires-python="&gt;=3.6">%s</a><br/>
</body></html>`, legacyName, sha(legacyTar), legacyName)
		case "/files/aa/bb/" + demoName:
			fileHits.Add(1)
			w.Write(demoWhl) //nolint:errcheck
		case "/files/aa/bb/" + demoName + ".metadata":
			w.Write([]byte(demoMeta)) //nolint:errcheck
		case "/files/dd/demo-0.8.tar.gz":
			w.Write(corrupt) //nolint:errcheck
		case "/files/ee/" + legacyName:
			w.Write(legacyTar) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("pypi-remote", "pypi", "proxy", map[string]any{
		"anonymousRead": true,
		"proxy":         map[string]any{"remoteUrl": upstream.URL},
	})
	inst.CreateRepo("pypi-local", "pypi", "hosted", nil)
	inst.CreateRepo("pypi-all", "pypi", "group", map[string]any{
		"anonymousRead": true,
		"group":         map[string]any{"members": []string{"pypi-local", "pypi-remote"}},
	})

	// Proxy project page: links are rewritten to go through Entrepot.
	for i := 0; i < 2; i++ {
		page := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/simple/demo/", "", nil), http.StatusOK)
		if strings.Contains(page, upstream.URL) || !strings.Contains(page, `href="../../packages/demo/1.0/`+demoName+`#sha256=`+sha(demoWhl)+`"`) ||
			!strings.Contains(page, `data-yanked="broken"`) || !strings.Contains(page, `data-core-metadata="sha256=`+sha([]byte(demoMeta))) {
			t.Fatalf("proxy page:\n%s", page)
		}
	}
	if indexHits.Load() != 1 {
		t.Fatalf("index fetched %d times, want 1 (cached)", indexHits.Load())
	}
	js := getJSON(t, inst, "/repository/pypi-remote/simple/demo/", "")
	if len(js.Files) != 3 || len(js.Versions) != 3 || js.Files[0].Size != int64(len(demoWhl)) {
		t.Fatalf("proxy json: %+v", js)
	}

	// Files are fetched once and cached; metadata is proxied too.
	for i := 0; i < 3; i++ {
		got := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/packages/demo/1.0/"+demoName, "", nil), http.StatusOK)
		if got != string(demoWhl) {
			t.Fatal("proxied wheel differs")
		}
	}
	if fileHits.Load() != 1 {
		t.Fatalf("file fetched %d times", fileHits.Load())
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/packages/demo/1.0/"+demoName+".metadata", "", nil), http.StatusOK); got != demoMeta {
		t.Fatalf("metadata %q", got)
	}
	// A file whose content does not match the published digest is rejected
	// and not cached.
	resp := inst.Do("GET", "/repository/pypi-remote/packages/demo/0.8/demo-0.8.tar.gz", "", nil)
	if resp.StatusCode < 500 {
		t.Fatalf("corrupt upstream file served with %d", resp.StatusCode)
	}
	testutil.Body(resp)
	var assets struct {
		Items []struct {
			Path string `json:"path"`
		} `json:"items"`
	}
	inst.JSON("GET", "/repositories/pypi-remote/assets", nil, http.StatusOK, &assets)
	for _, a := range assets.Items {
		if strings.Contains(a.Path, "demo-0.8") {
			t.Fatalf("corrupt file was cached: %s", a.Path)
		}
	}
	// Wrong version segment / unknown files.
	testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/packages/demo/2.0/"+demoName, "", nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/simple/missing/", "", nil), http.StatusNotFound)

	// HTML upstream pages are understood too.
	page := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/simple/legacy-proj/", "", nil), http.StatusOK)
	if !strings.Contains(page, `href="../../packages/legacy-proj/0.5/`+legacyName+`#sha256=`+sha(legacyTar)+`"`) || !strings.Contains(page, `data-requires-python="&gt;=3.6"`) {
		t.Fatalf("html proxy page:\n%s", page)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/packages/legacy-proj/0.5/"+legacyName, "", nil), http.StatusOK); got != string(legacyTar) {
		t.Fatal("legacy sdist differs")
	}
	// Proxy root index lists cached projects.
	root := testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/simple/", "", nil), http.StatusOK)
	if !strings.Contains(root, `href="demo/"`) || !strings.Contains(root, `href="legacy-proj/"`) {
		t.Fatalf("proxy root: %s", root)
	}
	// Components are recorded for cached files.
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/repositories/pypi-remote/components", nil, http.StatusOK, &comps)
	if len(comps) != 2 {
		t.Fatalf("proxy components: %+v", comps)
	}
	// Proxies do not accept uploads.
	testutil.Expect(t, twineUpload(t, inst, "pypi-remote", testutil.BootstrapToken, map[string]string{"name": "demo", "version": "1.0"}, demoName, demoWhl), http.StatusMethodNotAllowed)

	// Group merges the hosted and proxied files for a project.
	localWhl, localName := wheel(t, "demo", "2.0", ">=3.8")
	testutil.Expect(t, twineUpload(t, inst, "pypi-local", testutil.BootstrapToken, map[string]string{"name": "demo", "version": "2.0"}, localName, localWhl), http.StatusOK)
	js = getJSON(t, inst, "/repository/pypi-all/simple/demo/", "")
	names := map[string]string{}
	for _, f := range js.Files {
		names[f.Filename] = f.URL
	}
	if len(js.Files) != 4 || names[localName] == "" || names[demoName] == "" {
		t.Fatalf("group page: %+v", js)
	}
	for _, fn := range []string{localName, demoName} {
		p := resolve(t, "/repository/pypi-all/simple/demo/", names[fn])
		if !strings.HasPrefix(p, "/repository/pypi-all/packages/demo/") {
			t.Fatalf("group link %s", p)
		}
		testutil.Expect(t, inst.Do("GET", p, "", nil), http.StatusOK)
	}
	groupRoot := testutil.Expect(t, inst.Do("GET", "/repository/pypi-all/simple/", "", nil), http.StatusOK)
	if regexp.MustCompile(`href="demo/"`).FindAllStringIndex(groupRoot, -1) == nil {
		t.Fatalf("group root: %s", groupRoot)
	}
	testutil.Expect(t, twineUpload(t, inst, "pypi-all", testutil.BootstrapToken, map[string]string{"name": "demo", "version": "1.0"}, demoName, demoWhl), http.StatusMethodNotAllowed)

	// Deleting a cached index forces a refetch.
	testutil.Expect(t, inst.Do("DELETE", "/repository/pypi-remote/simple/demo", testutil.BootstrapToken, nil), http.StatusNoContent)
	testutil.Expect(t, inst.Do("GET", "/repository/pypi-remote/simple/demo/", "", nil), http.StatusOK)
	if indexHits.Load() < 2 {
		t.Fatal("index was not refetched after delete")
	}
	_ = io.Discard
}
