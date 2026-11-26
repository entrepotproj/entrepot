package scan_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/scan/drivers/mdfake"
	"github.com/entrepotproj/entrepot/internal/testutil"
)

// newMDInst starts an instance with a MetaDefender scanner "md" backed by a
// fake server.
func newMDInst(t *testing.T, opts ...testutil.Option) (*testutil.Instance, *mdfake.Server) {
	t.Helper()
	srv := mdfake.New()
	t.Cleanup(srv.Close)
	inst := newInst(t, opts...)
	svc := inst.App.Scan
	svc.FilePollMin, svc.FilePollMax, svc.FileBusyBackoff = 5*time.Millisecond, 20*time.Millisecond, 5*time.Millisecond
	inst.JSON("POST", "/scanners", map[string]any{"name": "md", "type": "metadefender",
		"metadefender": map[string]any{"url": srv.URL, "rule": "Packages", "timeoutSeconds": 20,
			"webUrl": "https://md.example/#/public/process/dataId/{dataId}"}}, http.StatusCreated, nil)
	return inst, srv
}

// markedWheel is a wheel with an uncompressed file holding marker (the
// fake MetaDefender's verdict).
func markedWheel(t *testing.T, name, version, marker string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dist := strings.ReplaceAll(name, "-", "_") + "-" + version
	for n, c := range map[string]string{
		dist + ".dist-info/METADATA": "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n",
		dist + ".dist-info/WHEEL":    "Wheel-Version: 1.0\nTag: py3-none-any\n",
		name + "/payload.bin":        "payload " + marker,
	} {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(c))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), dist + "-py3-none-any.whl"
}

type mdScans struct {
	Results []struct {
		Scanner  string `json:"scanner"`
		Status   string `json:"status"`
		Findings []struct {
			VulnID           string `json:"vulnId"`
			Kind             string `json:"kind"`
			Severity         string `json:"severity"`
			Package          string `json:"package"`
			InstalledVersion string `json:"installedVersion"`
			URL              string `json:"url"`
		} `json:"findings"`
		Files []struct {
			Name   string `json:"name"`
			DataID string `json:"dataId"`
			Result string `json:"result"`
			Cached bool   `json:"cached"`
		} `json:"files"`
	} `json:"results"`
}

func mdResults(t *testing.T, inst *testutil.Instance, id string) mdScans {
	t.Helper()
	var s mdScans
	inst.JSON("GET", "/components/"+id+"/scans", nil, http.StatusOK, &s)
	return s
}

// Uploads are analysed by MetaDefender before they can be downloaded:
// a clean wheel is held, then served; an infected one is blocked with the
// threat's name, and only a waiver for that exact threat releases it.
func TestMetaDefenderScansUploads(t *testing.T) {
	inst, srv := newMDInst(t)
	srv.PollsBeforeDone = 3
	inst.CreateRepo("py-md", "pypi", "hosted", scanSettings([]string{"md"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "holdSeconds": 30}))
	startWorkers(t, inst)

	good, goodName := markedWheel(t, "good", "1.0", "")
	testutil.Expect(t, uploadFile(t, inst, "py-md", goodName, good), http.StatusCreated)
	r := await(t, getAsync(inst, "/repository/py-md/packages/good/1.0/"+goodName))
	if r.code != http.StatusOK || r.body != string(good) {
		t.Fatalf("clean wheel: %d %s", r.code, r.body)
	}
	gc := findComponent(t, inst, "py-md", "good", "1.0")
	res := mdResults(t, inst, gc.ID).Results
	if len(res) != 1 || res[0].Status != "ok" || len(res[0].Files) != 1 ||
		res[0].Files[0].Name != "packages/good/1.0/"+goodName || res[0].Files[0].Result != "No Threat Detected" {
		t.Fatalf("clean results: %+v", res)
	}
	// The derived .metadata sidecar is not sent.
	for _, a := range srv.Analyses() {
		if strings.HasSuffix(a.Name, ".metadata") || a.Rule != "Packages" {
			t.Fatalf("analysis: %+v", a)
		}
	}

	evil, evilName := markedWheel(t, "evil", "1.0", "X-MDFAKE-MALWARE")
	testutil.Expect(t, uploadFile(t, inst, "py-md", evilName, evil), http.StatusCreated)
	url := "/repository/py-md/packages/evil/1.0/" + evilName
	r = await(t, getAsync(inst, url))
	want := "MALWARE:Virus eicar test file detected by md in packages/evil/1.0/" + evilName + " (evil@1.0)"
	if r.code != http.StatusForbidden || !strings.Contains(r.body, want) || r.header.Get("X-Entrepot-Quarantined") != "true" {
		t.Fatalf("infected wheel: %d %s", r.code, r.body)
	}
	ec := findComponent(t, inst, "py-md", "evil", "1.0")
	res = mdResults(t, inst, ec.ID).Results
	if len(res) != 1 || len(res[0].Findings) != 1 {
		t.Fatalf("infected results: %+v", res)
	}
	f := res[0].Findings[0]
	if f.Kind != "malware" || f.Severity != "critical" || f.Package != "packages/evil/1.0/"+evilName ||
		f.URL != "https://md.example/#/public/process/dataId/"+res[0].Files[0].DataID {
		t.Fatalf("finding: %+v", f)
	}

	// A "*" waiver does not cover threats; the exact id does.
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "*", "componentPattern": "evil", "reason": "all"}, http.StatusCreated, nil)
	// The verdict computed with the current waivers still quarantines.
	if s := getScans(t, inst, ec.ID); !s.Quarantined || s.Results[0].Findings[0].Waived {
		t.Fatalf("\"*\" waiver covered a threat: %+v", s)
	}
	waitState(t, inst, ec.ID, "vulnerable")
	testutil.Expect(t, inst.Do("GET", url, testutil.BootstrapToken, nil), http.StatusForbidden)
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": f.VulnID, "componentPattern": "evil", "reason": "test file"},
		http.StatusCreated, nil)
	waitFor(t, func() bool { return inst.Do("GET", url, testutil.BootstrapToken, nil).StatusCode == http.StatusOK })
}

// MetaDefender failing fails closed with blockOnError: downloads are
// blocked until a retry succeeds.
func TestMetaDefenderFailClosed(t *testing.T) {
	inst, srv := newMDInst(t, func(c *config.Config) { c.Scan.ErrorRetryInterval = time.Millisecond })
	srv.Broken = true
	inst.CreateRepo("py-closed", "pypi", "hosted", scanSettings([]string{"md"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "blockOnError": true}))
	startWorkers(t, inst)

	whl, name := markedWheel(t, "demo", "1.0", "")
	testutil.Expect(t, uploadFile(t, inst, "py-closed", name, whl), http.StatusCreated)
	c := findComponent(t, inst, "py-closed", "demo", "1.0")
	s := waitState(t, inst, c.ID, "error")
	if !strings.Contains(s.Results[0].Error, "MetaDefender answered 500") {
		t.Fatalf("error: %+v", s.Results)
	}
	url := "/repository/py-closed/packages/demo/1.0/" + name
	if b := testutil.Expect(t, inst.Do("GET", url, testutil.BootstrapToken, nil), http.StatusForbidden); !strings.Contains(b, "could not be scanned") {
		t.Fatalf("body: %s", b)
	}

	srv.Do(func(s *mdfake.Server) { s.Broken = false })
	if n, err := inst.App.Scan.RetryNow(context.Background()); err != nil || n != 1 {
		t.Fatalf("retries = %d, %v", n, err)
	}
	waitState(t, inst, c.ID, "clean")
	testutil.Expect(t, inst.Do("GET", url, testutil.BootstrapToken, nil), http.StatusOK)
}

// The first pull through a proxy is held while MetaDefender analyses the
// freshly cached tarball; an infected upstream tarball is blocked.
func TestMetaDefenderProxyPull(t *testing.T) {
	tarballs := map[string][]byte{
		"left-pad": []byte("tarball bytes of left-pad 1.3.0"),
		"evil":     []byte("tarball bytes of evil 1.0.0 X-MDFAKE-MALWARE"),
	}
	versions := map[string]string{"left-pad": "1.3.0", "evil": "1.0.0"}
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, tgz := range tarballs {
			v := versions[name]
			file := "/" + name + "/-/" + name + "-" + v + ".tgz"
			switch r.URL.Path {
			case "/" + name:
				s1, s512 := sha1.Sum(tgz), sha512.Sum512(tgz)
				_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "dist-tags": map[string]string{"latest": v},
					"versions": map[string]any{v: map[string]any{"name": name, "version": v,
						"dist": map[string]any{"tarball": upstream.URL + file, "shasum": hex.EncodeToString(s1[:]),
							"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:])}}}})
				return
			case file:
				_, _ = w.Write(tgz)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(upstream.Close)
	inst, srv := newMDInst(t)
	srv.PollsBeforeDone = 5
	settings := scanSettings([]string{"md"}, "quarantine", map[string]any{"blockUntilScanned": true, "holdSeconds": 30})
	settings["proxy"] = map[string]any{"remoteUrl": upstream.URL}
	inst.CreateRepo("npm-md", "npm", "proxy", settings)
	startWorkers(t, inst)

	r := await(t, getAsync(inst, "/repository/npm-md/left-pad/-/left-pad-1.3.0.tgz"))
	if r.code != http.StatusOK || r.body != string(tarballs["left-pad"]) {
		t.Fatalf("first pull: %d %s", r.code, r.body)
	}
	r = await(t, getAsync(inst, "/repository/npm-md/evil/-/evil-1.0.0.tgz"))
	if r.code != http.StatusForbidden || !strings.Contains(r.body, "MALWARE:Virus eicar test file") {
		t.Fatalf("infected pull: %d %s", r.code, r.body)
	}
	if up, _, _ := srv.Counts(); up != 2 {
		t.Fatalf("uploads: %d", up)
	}
}

// Helm charts can be scanned by file scanners (the .prov sidecar is not
// sent); a second repository holding the same chart reuses the analysis.
func TestMetaDefenderHelmChart(t *testing.T) {
	inst, srv := newMDInst(t)
	inst.CreateRepo("charts", "helm", "hosted", scanSettings([]string{"md"}, "quarantine", nil))
	inst.CreateRepo("charts2", "helm", "hosted", scanSettings([]string{"md"}, "quarantine", nil))
	startWorkers(t, inst)

	tgz := helmChart(t, "demo", "0.1.0")
	for _, repoName := range []string{"charts", "charts2"} {
		testutil.Expect(t, inst.Do("PUT", "/repository/"+repoName+"/charts/demo-0.1.0.tgz", testutil.BootstrapToken,
			bytes.NewReader(tgz)), http.StatusCreated)
		c := findComponent(t, inst, repoName, "demo", "0.1.0")
		s := waitState(t, inst, c.ID, "clean")
		if len(s.Results) != 1 || s.Results[0].Status != "ok" {
			t.Fatalf("%s: %+v", repoName, s.Results)
		}
	}
	if up, _, _ := srv.Counts(); up != 1 {
		t.Fatalf("uploads: %d", up)
	}
	c := findComponent(t, inst, "charts2", "demo", "0.1.0")
	if f := mdResults(t, inst, c.ID).Results[0].Files; len(f) != 1 || !f[0].Cached || f[0].Name != "charts/demo-0.1.0.tgz" {
		t.Fatalf("files: %+v", f)
	}
}

func helmChart(t *testing.T, name, version string) []byte {
	t.Helper()
	files := map[string]string{
		name + "/Chart.yaml":  "apiVersion: v2\nname: " + name + "\nversion: " + version + "\n",
		name + "/values.yaml": "replicas: 1\n",
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, c := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(c))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A component in a repository with MetaDefender and a faster scanner
// stays pending until MetaDefender has reported too.
func TestMetaDefenderStrictWithOtherScanners(t *testing.T) {
	hook := newFakeWebhook(t, "s", cleanReport)
	inst, srv := newMDInst(t)
	srv.Never = true
	createHook(t, inst, "fast", hook)
	inst.CreateRepo("py-both", "pypi", "hosted", scanSettings([]string{"fast", "md"}, "quarantine",
		map[string]any{"blockUntilScanned": true}))
	startWorkers(t, inst)

	whl, name := markedWheel(t, "demo", "1.0", "")
	testutil.Expect(t, uploadFile(t, inst, "py-both", name, whl), http.StatusCreated)
	c := findComponent(t, inst, "py-both", "demo", "1.0")
	waitFor(t, func() bool { return hasResult(t, inst, c.ID, "fast") })
	if st := storedState(t, inst, c.ID); st != "pending" {
		t.Fatalf("state after the fast scanner: %s", st)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/py-both/packages/demo/1.0/"+name, testutil.BootstrapToken, nil), http.StatusForbidden)
	srv.Do(func(s *mdfake.Server) { s.Never = false })
	waitState(t, inst, c.ID, "clean")
}

func TestMetaDefenderScannerAPI(t *testing.T) {
	srv := mdfake.New()
	defer srv.Close()
	srv.APIKey = "md-key-123"
	inst := newInst(t)
	inst.JSON("POST", "/scanners", map[string]any{"name": "md", "type": "metadefender",
		"metadefender": map[string]any{"url": srv.URL + "/", "apiKey": "md-key-123", "rule": "Packages", "concurrency": 8,
			"hashLookup": false}}, http.StatusCreated, nil)
	var got map[string]any
	inst.JSON("GET", "/scanners/md", nil, http.StatusOK, &got)
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "md-key-123") || strings.Contains(string(raw), "apiKey") ||
		!strings.Contains(string(raw), `"url":"`+srv.URL+`"`) || !strings.Contains(string(raw), `"hashLookup":false`) {
		t.Fatalf("scanner: %s", raw)
	}
	var stored string
	_ = inst.App.Pool.QueryRow(context.Background(), `SELECT config::text FROM scanners WHERE name='md'`).Scan(&stored)
	if strings.Contains(stored, "md-key-123") || !strings.Contains(stored, "enc:v1:") {
		t.Fatalf("api key not sealed: %s", stored)
	}
	var res struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
		Version string `json:"version"`
	}
	inst.JSON("POST", "/scanners/md/test", nil, http.StatusOK, &res)
	if !res.OK || res.Version != "5.24.2" || !strings.Contains(res.Message, `rule "Packages" is available (files up to 1024 MB)`) {
		t.Fatalf("test: %+v", res)
	}

	// An update without the key keeps it for the same server only.
	update := func(url, rule string) {
		inst.JSON("PUT", "/scanners/md", map[string]any{"name": "md", "type": "metadefender",
			"metadefender": map[string]any{"url": url, "rule": rule}}, http.StatusOK, nil)
	}
	update(srv.URL, "Packages")
	inst.JSON("POST", "/scanners/md/test", nil, http.StatusOK, &res)
	if !res.OK {
		t.Fatalf("key not kept: %+v", res)
	}
	update(srv.URL, "Missing")
	inst.JSON("POST", "/scanners/md/test", nil, http.StatusOK, &res)
	if res.OK || !strings.Contains(res.Message, `rule "Missing" is not available`) {
		t.Fatalf("missing rule: %+v", res)
	}
	update(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), "Packages")
	inst.JSON("POST", "/scanners/md/test", nil, http.StatusOK, &res)
	if res.OK || !strings.Contains(res.Message, "check metadefender.apiKey") {
		t.Fatalf("key sent to a new URL: %+v", res)
	}

	for _, bad := range []map[string]any{
		{},
		{"url": "ftp://md"},
		{"url": srv.URL, "concurrency": 99},
		{"url": srv.URL, "maxResultAgeHours": -1},
		{"url": srv.URL, "webUrl": "javascript:alert(1)"},
		{"url": srv.URL, "caCertificate": "not a certificate"},
	} {
		inst.JSON("POST", "/scanners", map[string]any{"name": "md2", "type": "metadefender", "metadefender": bad},
			http.StatusBadRequest, nil)
	}
}
