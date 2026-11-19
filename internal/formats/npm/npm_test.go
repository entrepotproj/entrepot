package npm_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/entrepotproj/entrepot/internal/testutil"
)

// tarball builds an npm package tarball.
func tarball(t *testing.T, name, version string, extra map[string]any) []byte {
	t.Helper()
	pj := map[string]any{"name": name, "version": version, "description": "The " + name + " package", "license": "MIT", "main": "index.js"}
	for k, v := range extra {
		pj[k] = v
	}
	pjBytes, _ := json.Marshal(pj)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, c := range map[string][]byte{"package/package.json": pjBytes, "package/index.js": []byte("module.exports = 1\n"), "package/README.md": []byte("# " + name + "\n")} {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write(c)                                                                                   //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	gz.Close() //nolint:errcheck
	return buf.Bytes()
}

func integrity(b []byte) (string, string) {
	s1 := sha1.Sum(b) //nolint:gosec
	s5 := sha512.Sum512(b)
	return hex.EncodeToString(s1[:]), "sha512-" + base64.StdEncoding.EncodeToString(s5[:])
}

func unscoped(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// publishBody builds the document `npm publish` sends.
func publishBody(name, version string, tgz []byte, tag string, dist map[string]any) []byte {
	file := unscoped(name) + "-" + version + ".tgz"
	shasum, integ := integrity(tgz)
	if dist == nil {
		dist = map[string]any{"shasum": shasum, "integrity": integ, "tarball": "http://registry.example/" + name + "/-/" + file}
	}
	body := map[string]any{
		"_id": name, "name": name, "description": "The " + name + " package",
		"dist-tags": map[string]string{tag: version},
		"versions": map[string]any{version: map[string]any{
			"name": name, "version": version, "description": "The " + name + " package", "license": "MIT",
			"readme": "# " + name, "scripts": map[string]string{"test": "true"}, "dependencies": map[string]string{},
			"dist": dist,
		}},
		"access":       nil,
		"_attachments": map[string]any{file: map[string]any{"content_type": "application/octet-stream", "data": base64.StdEncoding.EncodeToString(tgz), "length": len(tgz)}},
	}
	b, _ := json.Marshal(body)
	return b
}

type packument struct {
	ID       string            `json:"_id"`
	Rev      string            `json:"_rev"`
	Name     string            `json:"name"`
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Deprecated string `json:"deprecated"`
		Readme     string `json:"readme"`
		Dist       struct {
			Tarball   string `json:"tarball"`
			Shasum    string `json:"shasum"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	} `json:"versions"`
	Time     map[string]any `json:"time"`
	Readme   string         `json:"readme"`
	Modified string         `json:"modified"`
}

func getPackument(t *testing.T, inst *testutil.Instance, path, token string, headers ...string) (packument, http.Header) {
	t.Helper()
	resp := inst.Do("GET", path, token, nil, headers...)
	body := testutil.Expect(t, resp, http.StatusOK)
	var p packument
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return p, resp.Header
}

func rawDoc(t *testing.T, inst *testutil.Instance, path, token string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", path, token, nil), http.StatusOK)), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func put(inst *testutil.Instance, path, token string, body []byte) *http.Response {
	return inst.Do("PUT", path, token, bytes.NewReader(body), "Content-Type", "application/json")
}

func TestHostedNpm(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("npm-local", "npm", "hosted", nil)
	writer := inst.Token("ci", "developer", "npm-local")
	reader := inst.Token("viewer", "viewer", "*")
	base := inst.URL + "/repository/npm-local/"

	v100 := tarball(t, "demo", "1.0.0", nil)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", "", publishBody("demo", "1.0.0", v100, "latest", nil)), http.StatusUnauthorized)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", reader, publishBody("demo", "1.0.0", v100, "latest", nil)), http.StatusForbidden)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", writer, publishBody("demo", "1.0.0", v100, "latest", map[string]any{"shasum": "0000"})), http.StatusBadRequest)
	testutil.Expect(t, put(inst, "/repository/npm-local/other", writer, publishBody("demo", "1.0.0", v100, "latest", nil)), http.StatusBadRequest)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", writer, publishBody("demo", "1.0.0", v100, "latest", nil)), http.StatusCreated)
	// Republishing a version is refused.
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", writer, publishBody("demo", "1.0.0", tarball(t, "demo", "1.0.0", map[string]any{"x": 1}), "latest", nil)), http.StatusConflict)
	v110 := tarball(t, "demo", "1.1.0", nil)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", writer, publishBody("demo", "1.1.0", v110, "latest", nil)), http.StatusCreated)

	p, hdr := getPackument(t, inst, "/repository/npm-local/demo", reader)
	shasum, integ := integrity(v100)
	v := p.Versions["1.0.0"]
	if p.Name != "demo" || p.DistTags["latest"] != "1.1.0" || len(p.Versions) != 2 || p.Rev == "" ||
		v.Dist.Tarball != base+"demo/-/demo-1.0.0.tgz" || v.Dist.Shasum != shasum || v.Dist.Integrity != integ || p.Time["1.0.0"] == nil {
		t.Fatalf("packument: %+v", p)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo/-/demo-1.0.0.tgz", reader, nil), http.StatusOK); got != string(v100) {
		t.Fatal("tarball differs")
	}
	// Conditional GET.
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo", reader, nil, "If-None-Match", hdr.Get("ETag")), http.StatusNotModified)
	// Abbreviated metadata.
	resp := inst.Do("GET", "/repository/npm-local/demo", reader, nil, "Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*")
	if ct := resp.Header.Get("Content-Type"); ct != "application/vnd.npm.install-v1+json" {
		t.Fatalf("abbreviated content type %q", ct)
	}
	body := testutil.Expect(t, resp, http.StatusOK)
	if strings.Contains(body, "readme") || !strings.Contains(body, `"modified"`) || !strings.Contains(body, base+"demo/-/demo-1.1.0.tgz") {
		t.Fatalf("abbreviated: %s", body)
	}
	// Single version and dist-tag lookups.
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo/latest", reader, nil), http.StatusOK); !strings.Contains(b, `"version":"1.1.0"`) {
		t.Fatalf("latest: %s", b)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo/9.9.9", reader, nil), http.StatusNotFound)

	// Scoped packages, both URL forms.
	sc := tarball(t, "@acme/widget", "0.1.0", nil)
	testutil.Expect(t, put(inst, "/repository/npm-local/@acme%2fwidget", writer, publishBody("@acme/widget", "0.1.0", sc, "latest", nil)), http.StatusCreated)
	for _, path := range []string{"/repository/npm-local/@acme%2fwidget", "/repository/npm-local/@acme%2Fwidget", "/repository/npm-local/@acme/widget"} {
		sp, _ := getPackument(t, inst, path, reader)
		if sp.Versions["0.1.0"].Dist.Tarball != base+"@acme/widget/-/widget-0.1.0.tgz" {
			t.Fatalf("scoped tarball url: %+v", sp)
		}
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/@acme/widget/-/widget-0.1.0.tgz", reader, nil), http.StatusOK); got != string(sc) {
		t.Fatal("scoped tarball differs")
	}

	// dist-tags.
	testutil.Expect(t, put(inst, "/repository/npm-local/-/package/demo/dist-tags/beta", reader, []byte(`"1.0.0"`)), http.StatusForbidden)
	testutil.Expect(t, put(inst, "/repository/npm-local/-/package/demo/dist-tags/beta", writer, []byte(`"1.0.0"`)), http.StatusOK)
	testutil.Expect(t, put(inst, "/repository/npm-local/-/package/demo/dist-tags/beta", writer, []byte(`"7.0.0"`)), http.StatusNotFound)
	if tags := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/-/package/demo/dist-tags", reader, nil), http.StatusOK); !strings.Contains(tags, `"beta":"1.0.0"`) {
		t.Fatalf("tags: %s", tags)
	}
	var comps []struct {
		Version string         `json:"version"`
		Attrs   map[string]any `json:"attrs"`
	}
	inst.JSON("GET", "/repositories/npm-local/components?q=demo", nil, http.StatusOK, &comps)
	for _, c := range comps {
		if c.Version == "1.0.0" && fmt.Sprint(c.Attrs["distTags"]) != "[beta]" {
			t.Fatalf("component dist-tags: %+v", c)
		}
		if c.Attrs["description"] != "The demo package" {
			t.Fatalf("component attrs: %+v", c)
		}
	}
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/-/package/demo/dist-tags/beta", writer, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/-/package/demo/dist-tags/latest", writer, nil), http.StatusBadRequest)

	// whoami / login.
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/-/whoami", writer, nil), http.StatusOK); !strings.Contains(b, "username") {
		t.Fatalf("whoami: %s", b)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/-/whoami", "", nil), http.StatusUnauthorized)
	login := testutil.Expect(t, put(inst, "/repository/npm-local/-/user/org.couchdb.user:bob", "", []byte(`{"name":"bob","password":"`+writer+`"}`)), http.StatusCreated)
	if !strings.Contains(login, `"token":"`+writer+`"`) {
		t.Fatalf("login: %s", login)
	}
	testutil.Expect(t, put(inst, "/repository/npm-local/-/user/org.couchdb.user:bob", "", []byte(`{"name":"bob","password":"wrong"}`)), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("POST", "/repository/npm-local/-/v1/login", "", nil), http.StatusNotFound)

	// Search.
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/-/v1/search?text=dem&size=5", reader, nil), http.StatusOK); !strings.Contains(b, `"name":"demo","scope":"unscoped","version":"1.1.0"`) && !strings.Contains(b, `"version":"1.1.0"`) {
		t.Fatalf("search: %s", b)
	}
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/-/v1/search?text=nothing", reader, nil), http.StatusOK); !strings.Contains(b, `"objects":[]`) {
		t.Fatalf("empty search: %s", b)
	}

	// Deprecate: PUT the modified packument.
	doc := rawDoc(t, inst, "/repository/npm-local/demo?write=true", writer)
	doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["deprecated"] = "use 1.1"
	b, _ := json.Marshal(doc)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo", writer, b), http.StatusOK)
	p, _ = getPackument(t, inst, "/repository/npm-local/demo", reader)
	if p.Versions["1.0.0"].Deprecated != "use 1.1" {
		t.Fatalf("deprecate: %+v", p.Versions["1.0.0"])
	}

	// Unpublish one version (npm unpublish demo@1.0.0): stale revision,
	// missing delete permission, then success.
	doc = rawDoc(t, inst, "/repository/npm-local/demo?write=true", writer)
	rev := doc["_rev"].(string)
	delete(doc["versions"].(map[string]any), "1.0.0")
	b, _ = json.Marshal(doc)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo/-rev/0-stale", testutil.BootstrapToken, b), http.StatusConflict)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo/-rev/"+rev, writer, b), http.StatusForbidden)
	testutil.Expect(t, put(inst, "/repository/npm-local/demo/-rev/"+rev, testutil.BootstrapToken, b), http.StatusOK)
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/demo/-/demo-1.0.0.tgz/-rev/x", testutil.BootstrapToken, nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo/-/demo-1.0.0.tgz", reader, nil), http.StatusNotFound)
	p, _ = getPackument(t, inst, "/repository/npm-local/demo", reader)
	if len(p.Versions) != 1 || p.DistTags["latest"] != "1.1.0" {
		t.Fatalf("after unpublish: %+v", p)
	}

	// Generic API upload of an `npm pack` tarball.
	up := tarball(t, "uploaded", "2.0.0", nil)
	var mbody bytes.Buffer
	mw := multipart.NewWriter(&mbody)
	fw, _ := mw.CreateFormFile("file", "uploaded-2.0.0.tgz")
	fw.Write(up) //nolint:errcheck
	mw.Close()   //nolint:errcheck
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/npm-local/upload", testutil.BootstrapToken, &mbody, "Content-Type", mw.FormDataContentType()), http.StatusCreated)
	p, _ = getPackument(t, inst, "/repository/npm-local/uploaded", reader)
	if p.DistTags["latest"] != "2.0.0" || !strings.Contains(p.Readme, "# uploaded") {
		t.Fatalf("uploaded packument: %+v", p)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/uploaded/-/uploaded-2.0.0.tgz", reader, nil), http.StatusOK); got != string(up) {
		t.Fatal("uploaded tarball differs")
	}
	// Deleting the only tarball makes the package disappear.
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/uploaded/-/uploaded-2.0.0.tgz/-rev/1", writer, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/uploaded/-/uploaded-2.0.0.tgz/-rev/1", testutil.BootstrapToken, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/uploaded", reader, nil), http.StatusNotFound)

	// Unpublish the whole package.
	p, _ = getPackument(t, inst, "/repository/npm-local/demo?write=true", reader)
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-local/demo/-rev/"+p.Rev, testutil.BootstrapToken, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/demo", reader, nil), http.StatusNotFound)
	// The scoped package is untouched.
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/@acme/widget", reader, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/npm-local/..%2f..%2fx", reader, nil), http.StatusBadRequest)
}

func TestHostedNpmRedeploy(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("npm-local", "npm", "hosted", map[string]any{"hosted": map[string]any{"allowRedeploy": true}})
	a := tarball(t, "pkg", "1.0.0", nil)
	b := tarball(t, "pkg", "1.0.0", map[string]any{"changed": true})
	testutil.Expect(t, put(inst, "/repository/npm-local/pkg", testutil.BootstrapToken, publishBody("pkg", "1.0.0", a, "latest", nil)), http.StatusCreated)
	testutil.Expect(t, put(inst, "/repository/npm-local/pkg", testutil.BootstrapToken, publishBody("pkg", "1.0.0", b, "latest", nil)), http.StatusCreated)
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-local/pkg/-/pkg-1.0.0.tgz", testutil.BootstrapToken, nil), http.StatusOK); got != string(b) {
		t.Fatal("redeploy did not replace the tarball")
	}
}

func TestProxyAndGroupNpm(t *testing.T) {
	leftPad := tarball(t, "left-pad", "1.3.0", nil)
	node := tarball(t, "@types/node", "20.0.0", nil)
	corrupt := []byte("corrupt")
	var docHits, tgzHits atomic.Int32
	var upstream *httptest.Server
	doc := func(name string, versions map[string][]byte, tarballURL func(file string) string) map[string]any {
		vs := map[string]any{}
		tm := map[string]string{"created": "2020-01-01T00:00:00.000Z", "modified": "2021-01-01T00:00:00.000Z"}
		latest := ""
		for v, tgz := range versions {
			shasum, integ := integrity(tgz)
			if bytes.Equal(tgz, corrupt) {
				shasum, integ = integrity([]byte("the real content"))
			}
			file := unscoped(name) + "-" + v + ".tgz"
			vs[v] = map[string]any{"name": name, "version": v, "dependencies": map[string]string{},
				"dist": map[string]any{"tarball": tarballURL(file), "shasum": shasum, "integrity": integ}}
			tm[v] = "2020-06-01T00:00:00.000Z"
			if v > latest {
				latest = v
			}
		}
		return map[string]any{"_id": name, "_rev": "5-abc", "name": name, "dist-tags": map[string]string{"latest": latest},
			"versions": vs, "time": tm, "readme": "upstream readme"}
	}
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/left-pad":
			docHits.Add(1)
			w.Header().Set("ETag", `"lp1"`)
			if r.Header.Get("If-None-Match") == `"lp1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			json.NewEncoder(w).Encode(doc("left-pad", map[string][]byte{"1.3.0": leftPad, "1.2.0": corrupt}, func(f string) string { //nolint:errcheck
				return upstream.URL + "/left-pad/-/" + f
			}))
		case "/@types%2fnode":
			json.NewEncoder(w).Encode(doc("@types/node", map[string][]byte{"20.0.0": node}, func(f string) string { //nolint:errcheck
				return upstream.URL + "/cdn/types-node/" + f
			}))
		case "/left-pad/-/left-pad-1.3.0.tgz":
			tgzHits.Add(1)
			w.Write(leftPad) //nolint:errcheck
		case "/left-pad/-/left-pad-1.2.0.tgz":
			w.Write(corrupt) //nolint:errcheck
		case "/cdn/types-node/node-20.0.0.tgz":
			w.Write(node) //nolint:errcheck
		case "/-/v1/search":
			fmt.Fprintf(w, `{"objects":[{"package":{"name":"left-pad","version":"1.3.0"},"score":{"final":1},"searchScore":1}],"total":1,"time":"now"}`)
		case "/-/npm/v1/security/advisories/bulk":
			b, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, `{"echo":%s}`, b)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("npm-remote", "npm", "proxy", map[string]any{
		"anonymousRead": true,
		"proxy":         map[string]any{"remoteUrl": upstream.URL},
	})
	inst.CreateRepo("npm-local", "npm", "hosted", nil)
	inst.CreateRepo("npm-all", "npm", "group", map[string]any{
		"anonymousRead": true,
		// Merging hosted and proxied versions of a name needs preferHosted off.
		"group": map[string]any{"members": []string{"npm-local", "npm-remote"}, "preferHosted": false},
	})
	remote := inst.URL + "/repository/npm-remote/"

	for i := 0; i < 2; i++ {
		p, _ := getPackument(t, inst, "/repository/npm-remote/left-pad", "")
		if p.Versions["1.3.0"].Dist.Tarball != remote+"left-pad/-/left-pad-1.3.0.tgz" || p.Readme != "upstream readme" || p.Rev != "5-abc" {
			t.Fatalf("proxy packument: %+v", p)
		}
	}
	if docHits.Load() != 1 {
		t.Fatalf("packument fetched %d times", docHits.Load())
	}
	for i := 0; i < 3; i++ {
		if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-remote/left-pad/-/left-pad-1.3.0.tgz", "", nil), http.StatusOK); got != string(leftPad) {
			t.Fatal("proxied tarball differs")
		}
	}
	if tgzHits.Load() != 1 {
		t.Fatalf("tarball fetched %d times", tgzHits.Load())
	}
	// Scoped package whose tarballs live elsewhere upstream.
	sp, _ := getPackument(t, inst, "/repository/npm-remote/@types%2fnode", "")
	if sp.Versions["20.0.0"].Dist.Tarball != remote+"@types/node/-/node-20.0.0.tgz" {
		t.Fatalf("scoped proxy packument: %+v", sp)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-remote/@types/node/-/node-20.0.0.tgz", "", nil), http.StatusOK); got != string(node) {
		t.Fatal("scoped proxied tarball differs")
	}
	// Integrity mismatch is rejected and not cached.
	resp := inst.Do("GET", "/repository/npm-remote/left-pad/-/left-pad-1.2.0.tgz", "", nil)
	if resp.StatusCode < 500 {
		t.Fatalf("corrupt tarball served with %d", resp.StatusCode)
	}
	testutil.Body(resp)
	var assets struct {
		Items []struct {
			Path string `json:"path"`
		} `json:"items"`
	}
	inst.JSON("GET", "/repositories/npm-remote/assets", nil, http.StatusOK, &assets)
	for _, a := range assets.Items {
		if strings.Contains(a.Path, "1.2.0") {
			t.Fatalf("corrupt tarball cached: %s", a.Path)
		}
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-remote/left-pad/-/left-pad-9.9.9.tgz", "", nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/npm-remote/does-not-exist", "", nil), http.StatusNotFound)
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/repositories/npm-remote/components", nil, http.StatusOK, &comps)
	if len(comps) != 2 {
		t.Fatalf("proxy components: %+v", comps)
	}
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-remote/-/v1/search?text=left", "", nil), http.StatusOK); !strings.Contains(b, "left-pad") {
		t.Fatalf("proxy search: %s", b)
	}
	testutil.Expect(t, put(inst, "/repository/npm-remote/left-pad", testutil.BootstrapToken, publishBody("left-pad", "9.0.0", leftPad, "latest", nil)), http.StatusMethodNotAllowed)

	// Group: hosted versions merged with proxied ones, first member wins.
	mine := tarball(t, "left-pad", "9.0.0", nil)
	testutil.Expect(t, put(inst, "/repository/npm-local/left-pad", testutil.BootstrapToken, publishBody("left-pad", "9.0.0", mine, "latest", nil)), http.StatusCreated)
	group := inst.URL + "/repository/npm-all/"
	gp, _ := getPackument(t, inst, "/repository/npm-all/left-pad", "")
	if len(gp.Versions) != 3 || gp.DistTags["latest"] != "9.0.0" ||
		gp.Versions["1.3.0"].Dist.Tarball != group+"left-pad/-/left-pad-1.3.0.tgz" || gp.Versions["9.0.0"].Dist.Tarball != group+"left-pad/-/left-pad-9.0.0.tgz" {
		t.Fatalf("group packument: %+v", gp)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-all/left-pad/-/left-pad-9.0.0.tgz", "", nil), http.StatusOK); got != string(mine) {
		t.Fatal("group hosted tarball differs")
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-all/left-pad/-/left-pad-1.3.0.tgz", "", nil), http.StatusOK); got != string(leftPad) {
		t.Fatal("group proxied tarball differs")
	}
	gs, _ := getPackument(t, inst, "/repository/npm-all/@types/node", "")
	if gs.Versions["20.0.0"].Dist.Tarball != group+"@types/node/-/node-20.0.0.tgz" {
		t.Fatalf("group scoped: %+v", gs)
	}
	if b := testutil.Expect(t, inst.Do("GET", "/repository/npm-all/-/v1/search?text=left", "", nil), http.StatusOK); strings.Count(b, `"name":"left-pad"`) != 1 {
		t.Fatalf("group search: %s", b)
	}
	if tags := testutil.Expect(t, inst.Do("GET", "/repository/npm-all/-/package/left-pad/dist-tags", "", nil), http.StatusOK); !strings.Contains(tags, `"latest":"9.0.0"`) {
		t.Fatalf("group tags: %s", tags)
	}
	// Audit requests are forwarded to the proxy upstream.
	if b := testutil.Expect(t, inst.Do("POST", "/repository/npm-all/-/npm/v1/security/advisories/bulk", "", strings.NewReader(`{"left-pad":["1.3.0"]}`), "Content-Type", "application/json"), http.StatusOK); !strings.Contains(b, `"echo":{"left-pad"`) {
		t.Fatalf("audit: %s", b)
	}
	testutil.Expect(t, put(inst, "/repository/npm-all/left-pad", testutil.BootstrapToken, publishBody("left-pad", "9.0.1", mine, "latest", nil)), http.StatusMethodNotAllowed)
	// Purging the proxy cache for a package.
	before := docHits.Load()
	testutil.Expect(t, inst.Do("DELETE", "/repository/npm-remote/left-pad/-rev/x", testutil.BootstrapToken, nil), http.StatusOK)
	getPackument(t, inst, "/repository/npm-remote/left-pad", "")
	if docHits.Load() != before+1 {
		t.Fatalf("packument not refetched after purge (%d)", docHits.Load())
	}

	// preferHosted (the default): left-pad is published internally, so the
	// public versions are never merged in, whatever the member order.
	inst.CreateRepo("npm-safe", "npm", "group", map[string]any{
		"anonymousRead": true,
		"group":         map[string]any{"members": []string{"npm-remote", "npm-local"}},
	})
	var safeRepo struct {
		Group struct {
			PreferHosted bool `json:"preferHosted"`
		} `json:"group"`
	}
	inst.JSON("GET", "/repositories/npm-safe", nil, http.StatusOK, &safeRepo)
	if !safeRepo.Group.PreferHosted {
		t.Fatal("preferHosted should default to true")
	}
	safe := inst.URL + "/repository/npm-safe/"
	sp2, _ := getPackument(t, inst, "/repository/npm-safe/left-pad", "")
	if len(sp2.Versions) != 1 || sp2.DistTags["latest"] != "9.0.0" || sp2.Versions["9.0.0"].Dist.Tarball != safe+"left-pad/-/left-pad-9.0.0.tgz" {
		t.Fatalf("preferHosted packument: %+v", sp2)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-safe/left-pad/-/left-pad-1.3.0.tgz", "", nil), http.StatusNotFound)
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-safe/left-pad/-/left-pad-9.0.0.tgz", "", nil), http.StatusOK); got != string(mine) {
		t.Fatal("preferHosted tarball differs")
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/npm-safe/left-pad/9.0.0", "", nil), http.StatusOK); !strings.Contains(got, `"version":"9.0.0"`) {
		t.Fatalf("preferHosted version: %s", got)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-safe/left-pad/1.3.0", "", nil), http.StatusNotFound)
	// Names not published internally still come from the proxy.
	ns, _ := getPackument(t, inst, "/repository/npm-safe/@types%2fnode", "")
	if ns.Versions["20.0.0"].Dist.Tarball != safe+"@types/node/-/node-20.0.0.tgz" {
		t.Fatalf("preferHosted proxied package: %+v", ns)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-safe/@types/node/-/node-20.0.0.tgz", "", nil), http.StatusOK)
	// Nested groups: the hosted member of an inner group counts too.
	inst.CreateRepo("npm-outer", "npm", "group", map[string]any{
		"anonymousRead": true,
		"group":         map[string]any{"members": []string{"npm-remote", "npm-all"}},
	})
	op, _ := getPackument(t, inst, "/repository/npm-outer/left-pad", "")
	if len(op.Versions) != 1 || op.Versions["9.0.0"].Version != "9.0.0" {
		t.Fatalf("nested preferHosted packument: %+v", op)
	}
}
