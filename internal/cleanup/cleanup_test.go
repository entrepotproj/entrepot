package cleanup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm shasum
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func targz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write([]byte(files[n]))                                                                           //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	gz.Close() //nolint:errcheck
	return buf.Bytes()
}

func npmPublish(t *testing.T, inst *testutil.Instance, repoName, name, version string) {
	t.Helper()
	tgz := targz(t, map[string]string{"package/package.json": fmt.Sprintf(`{"name":%q,"version":%q}`, name, version)})
	sum := sha1.Sum(tgz) //nolint:gosec
	file := name + "-" + version + ".tgz"
	body, _ := json.Marshal(map[string]any{
		"_id": name, "name": name, "dist-tags": map[string]string{"latest": version},
		"versions": map[string]any{version: map[string]any{"name": name, "version": version,
			"dist": map[string]any{"shasum": hex.EncodeToString(sum[:]), "tarball": "http://x/" + name + "/-/" + file}}},
		"_attachments": map[string]any{file: map[string]any{"data": base64.StdEncoding.EncodeToString(tgz), "length": len(tgz)}},
	})
	testutil.Expect(t, inst.Do("PUT", "/repository/"+repoName+"/"+name, testutil.BootstrapToken, bytes.NewReader(body),
		"Content-Type", "application/json"), http.StatusCreated)
}

func upload(t *testing.T, inst *testutil.Instance, repoName, filename string, content []byte) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", filename)
	fw.Write(content) //nolint:errcheck
	mw.Close()        //nolint:errcheck
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/"+repoName+"/upload", testutil.BootstrapToken, &body,
		"Content-Type", mw.FormDataContentType()), http.StatusCreated)
}

func sdist(t *testing.T, name, version string) []byte {
	return targz(t, map[string]string{
		name + "-" + version + "/PKG-INFO": "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n",
	})
}

func helmChart(t *testing.T, name, version string) []byte {
	return targz(t, map[string]string{name + "/Chart.yaml": "apiVersion: v2\nname: " + name + "\nversion: " + version + "\n"})
}

type runResult struct {
	DryRun       bool     `json:"dryRun"`
	Repositories []string `json:"repositories"`
	Components   []struct {
		Name, Version string
	} `json:"components"`
	Assets int64 `json:"assets"`
	Bytes  int64 `json:"bytes"`
}

func (r runResult) versions() string {
	var out []string
	for _, c := range r.Components {
		out = append(out, c.Name+"@"+c.Version)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func backdate(t *testing.T, inst *testutil.Instance, repoName, versionLike string, days int) {
	t.Helper()
	_, err := inst.App.Pool.Exec(context.Background(), fmt.Sprintf(`UPDATE components SET created_at = now() - interval '%d days'
		WHERE repository_id = (SELECT id FROM repositories WHERE name=$1) AND version LIKE $2`, days), repoName, versionLike)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCleanupPolicies(t *testing.T) {
	inst := testutil.New(t)

	// Validation.
	for _, bad := range []map[string]any{
		{"name": "x", "criteria": map[string]any{}},
		{"name": "x", "criteria": map[string]any{"nameRegex": "("}},
		{"name": "x", "criteria": map[string]any{"versionRegex": "[a"}},
		{"name": "x", "format": "nope", "criteria": map[string]any{"keepLatest": 1}},
		{"name": "x", "format": "npm", "criteria": map[string]any{"untaggedOlderThanDays": 3}},
		{"name": "Bad Name", "criteria": map[string]any{"keepLatest": 1}},
	} {
		resp := inst.Do("POST", "/api/v1/cleanup-policies", testutil.BootstrapToken, strings.NewReader(mustJSON(bad)), "Content-Type", "application/json")
		testutil.Expect(t, resp, http.StatusBadRequest)
	}
	reader := inst.Token("reader", "viewer", "*")
	testutil.Expect(t, inst.Do("GET", "/api/v1/cleanup-policies", reader, nil), http.StatusForbidden)

	// npm: old versions, keeping the two newest.
	inst.CreateRepo("npm-h", "npm", "hosted", nil)
	for _, v := range []string{"1.0.0", "1.1.0", "2.0.0-beta.1", "2.0.0"} {
		npmPublish(t, inst, "npm-h", "left-pad", v)
	}
	npmPublish(t, inst, "npm-h", "fresh", "0.0.1")
	backdate(t, inst, "npm-h", "%", 40)
	backdate(t, inst, "npm-h", "0.0.1", 1)
	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "old-npm", "description": "Old npm versions", "format": "npm",
		"criteria": map[string]any{"publishedOlderThanDays": 30, "keepLatest": 2}}, http.StatusCreated, nil)
	inst.JSON("PUT", "/cleanup-policies/old-npm", map[string]any{"description": "Old npm versions!", "format": "npm",
		"criteria": map[string]any{"publishedOlderThanDays": 30, "keepLatest": 2}}, http.StatusOK, nil)
	var preview runResult
	inst.JSON("POST", "/cleanup-policies/old-npm/preview?repository=npm-h", nil, http.StatusOK, &preview)
	if !preview.DryRun || preview.versions() != "left-pad@1.0.0 left-pad@1.1.0" || preview.Assets != 2 || preview.Bytes == 0 {
		t.Fatalf("npm preview: %+v", preview)
	}
	inst.JSON("PUT", "/repositories/npm-h", map[string]any{"name": "npm-h", "format": "npm", "kind": "hosted", "blobStore": "default",
		"cleanup": map[string]any{"policies": []string{"old-npm"}}}, http.StatusOK, nil)
	var pol struct {
		Description  string   `json:"description"`
		Repositories []string `json:"repositories"`
	}
	inst.JSON("GET", "/cleanup-policies/old-npm", nil, http.StatusOK, &pol)
	if pol.Description != "Old npm versions!" || len(pol.Repositories) != 1 || pol.Repositories[0] != "npm-h" {
		t.Fatalf("policy: %+v", pol)
	}
	// Policies in use cannot be deleted.
	inst.JSON("DELETE", "/cleanup-policies/old-npm", nil, http.StatusConflict, nil)

	var dry runResult
	inst.JSON("POST", "/repositories/npm-h/cleanup?dryRun=true", nil, http.StatusOK, &dry)
	if !dry.DryRun || dry.versions() != preview.versions() {
		t.Fatalf("dry run: %+v", dry)
	}
	var run runResult
	inst.JSON("POST", "/repositories/npm-h/cleanup", nil, http.StatusOK, &run)
	if run.DryRun || run.versions() != preview.versions() || len(run.Repositories) != 1 {
		t.Fatalf("run: %+v", run)
	}
	var pk struct {
		Versions map[string]any `json:"versions"`
	}
	json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", "/repository/npm-h/left-pad", testutil.BootstrapToken, nil), http.StatusOK)), &pk) //nolint:errcheck
	if len(pk.Versions) != 2 || pk.Versions["2.0.0"] == nil || pk.Versions["2.0.0-beta.1"] == nil {
		t.Fatalf("packument after cleanup: %+v", pk.Versions)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/npm-h/left-pad/-/left-pad-1.0.0.tgz", testutil.BootstrapToken, nil), http.StatusNotFound)
	var events []struct {
		Action, Target string
		Details        map[string]any
	}
	inst.JSON("GET", "/audit-events", nil, http.StatusOK, &events)
	found := false
	for _, e := range events {
		if e.Action == "cleanup.run" && e.Target == "npm-h" && e.Details["components"] == float64(2) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cleanup.run audit event: %+v", events)
	}
	// Nothing left; repository admin rights are required.
	inst.JSON("POST", "/repositories/npm-h/cleanup", nil, http.StatusOK, &run)
	if len(run.Components) != 0 {
		t.Fatalf("second run: %+v", run)
	}
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/npm-h/cleanup", reader, nil), http.StatusForbidden)

	// PyPI: pre-releases only (PEP 440), run explicitly with ?policy=.
	inst.CreateRepo("pypi-h", "pypi", "hosted", nil)
	for _, v := range []string{"1.0", "1.1rc1", "1.1.dev2", "1.1"} {
		upload(t, inst, "pypi-h", "demo-"+v+".tar.gz", sdist(t, "demo", v))
	}
	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "pre", "criteria": map[string]any{"prereleaseOnly": true}}, http.StatusCreated, nil)
	// A policy restricted to another format does nothing.
	inst.JSON("POST", "/cleanup-policies/old-npm/preview?repository=pypi-h", nil, http.StatusOK, &preview)
	if len(preview.Components) != 0 {
		t.Fatalf("format restriction ignored: %+v", preview)
	}
	inst.JSON("POST", "/repositories/pypi-h/cleanup?policy=pre", nil, http.StatusOK, &run)
	if run.versions() != "demo@1.1.dev2 demo@1.1rc1" {
		t.Fatalf("pypi run: %+v", run)
	}
	page := testutil.Expect(t, inst.Do("GET", "/repository/pypi-h/simple/demo/", testutil.BootstrapToken, nil), http.StatusOK)
	if strings.Contains(page, "rc1") || strings.Contains(page, "dev2") || !strings.Contains(page, "demo-1.1.tar.gz") || !strings.Contains(page, "demo-1.0.tar.gz") {
		t.Fatalf("simple page after cleanup:\n%s", page)
	}

	// Helm: not downloaded for 30 days (never-downloaded count from
	// publication); the index is regenerated.
	inst.CreateRepo("helm-h", "helm", "hosted", nil)
	for _, v := range []string{"0.1.0", "0.2.0", "0.3.0"} {
		upload(t, inst, "helm-h", "demo-"+v+".tgz", helmChart(t, "demo", v))
	}
	upload(t, inst, "helm-h", "other-1.0.0.tgz", helmChart(t, "other", "1.0.0"))
	backdate(t, inst, "helm-h", "%", 40)
	testutil.Expect(t, inst.Do("GET", "/repository/helm-h/charts/demo-0.2.0.tgz", testutil.BootstrapToken, nil), http.StatusOK)
	waitDownloaded(t, inst, "helm-h", "charts/demo-0.2.0.tgz")
	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "unused", "format": "helm",
		"criteria": map[string]any{"lastDownloadedOlderThanDays": 30, "nameRegex": "^demo$"}}, http.StatusCreated, nil)
	inst.JSON("PUT", "/repositories/helm-h", map[string]any{"name": "helm-h", "format": "helm", "kind": "hosted", "blobStore": "default",
		"cleanup": map[string]any{"policies": []string{"unused"}}}, http.StatusOK, nil)
	// Scheduled runs go through RunAll.
	res, err := inst.App.Cleanup.RunAll(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 2 || len(res.Repositories) != 1 || res.Repositories[0] != "helm-h" {
		t.Fatalf("RunAll: %+v", res)
	}
	index := testutil.Expect(t, inst.Do("GET", "/repository/helm-h/index.yaml", testutil.BootstrapToken, nil), http.StatusOK)
	if strings.Contains(index, "version: 0.1.0") || strings.Contains(index, "version: 0.3.0") ||
		!strings.Contains(index, "version: 0.2.0") || !strings.Contains(index, "name: other") {
		t.Fatalf("index after cleanup:\n%s", index)
	}

	// Unused policies can be deleted.
	inst.JSON("DELETE", "/cleanup-policies/pre", nil, http.StatusNoContent, nil)
	inst.JSON("GET", "/cleanup-policies/pre", nil, http.StatusNotFound, nil)
	var list []struct{ Name string }
	inst.JSON("GET", "/cleanup-policies", nil, http.StatusOK, &list)
	if len(list) != 2 {
		t.Fatalf("policies: %+v", list)
	}

	// Only one replica runs the scheduled cleanup at a time.
	release, ok, err := inst.App.Store.TryAdvisoryLock(context.Background(), "entrepot:cleanup")
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, ok2, _ := inst.App.Store.TryAdvisoryLock(context.Background(), "entrepot:cleanup"); ok2 {
		t.Fatal("lock taken twice")
	}
	release()
}

func waitDownloaded(t *testing.T, inst *testutil.Instance, repoName, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		var ok bool
		err := inst.App.Pool.QueryRow(context.Background(), `SELECT last_downloaded_at IS NOT NULL FROM assets
			WHERE repository_id=(SELECT id FROM repositories WHERE name=$1) AND path=$2`, repoName, path).Scan(&ok)
		if err == nil && ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("download was not recorded")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
