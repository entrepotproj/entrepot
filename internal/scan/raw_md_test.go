package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entrepotproj/entrepot/internal/testutil"
)

func putRaw(t *testing.T, inst *testutil.Instance, repoName, path, content string) {
	t.Helper()
	testutil.Expect(t, inst.Do("PUT", "/repository/"+repoName+"/"+path, testutil.BootstrapToken, strings.NewReader(content)),
		http.StatusCreated)
}

func countComponents(t *testing.T, inst *testutil.Instance, repoName string) int {
	t.Helper()
	var n int
	if err := inst.App.Pool.QueryRow(context.Background(), `SELECT count(*) FROM components c JOIN repositories r
		ON r.id = c.repository_id WHERE r.name=$1`, repoName).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Raw files in repositories with scanning become components (named after
// their path) and are scanned and gated like packages: held, then served or
// blocked; replacing a file scans it again; deleting it removes it.
func TestMetaDefenderRawFiles(t *testing.T) {
	inst, srv := newMDInst(t)
	settings := scanSettings([]string{"md"}, "quarantine", map[string]any{"blockUntilScanned": true, "holdSeconds": 30})
	settings["hosted"] = map[string]any{"allowRedeploy": true}
	inst.CreateRepo("files-md", "raw", "hosted", settings)
	startWorkers(t, inst)

	putRaw(t, inst, "files-md", "tools/setup.sh", "#!/bin/sh\necho hello\n")
	r := await(t, getAsync(inst, "/repository/files-md/tools/setup.sh"))
	if r.code != http.StatusOK || r.body != "#!/bin/sh\necho hello\n" {
		t.Fatalf("clean file: %d %s", r.code, r.body)
	}
	c := findComponent(t, inst, "files-md", "tools/setup.sh", "")
	if s := mdResults(t, inst, c.ID).Results; len(s) != 1 || s[0].Files[0].Name != "tools/setup.sh" {
		t.Fatalf("results: %+v", s)
	}

	// Replacing the file with infected content: scanned again, blocked.
	putRaw(t, inst, "files-md", "tools/setup.sh", "#!/bin/sh\n# X-MDFAKE-MALWARE\n")
	r = await(t, getAsync(inst, "/repository/files-md/tools/setup.sh"))
	if r.code != http.StatusForbidden ||
		!strings.Contains(r.body, "MALWARE:Virus eicar test file detected by md in tools/setup.sh — downloads are blocked") {
		t.Fatalf("replaced file: %d %s", r.code, r.body)
	}
	if up, _, _ := srv.Counts(); up != 2 {
		t.Fatalf("uploads: %d", up)
	}

	// The generic upload API attaches components too; deleting removes them.
	testutil.Expect(t, uploadFile(t, inst, "files-md", "notes.txt", []byte("plain notes")), http.StatusCreated)
	nc := findComponent(t, inst, "files-md", "notes.txt", "")
	waitState(t, inst, nc.ID, "clean")
	testutil.Expect(t, inst.Do("DELETE", "/repository/files-md/notes.txt", testutil.BootstrapToken, nil), http.StatusNoContent)
	if n := countComponents(t, inst, "files-md"); n != 1 {
		t.Fatalf("components after delete: %d", n)
	}
}

// Raw proxies scan files when they are first cached.
func TestMetaDefenderRawProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/tool.tar.gz":
			_, _ = w.Write([]byte("tool release"))
		case "/dist/evil.tar.gz":
			_, _ = w.Write([]byte("evil release X-MDFAKE-ARCHIVE"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	inst, _ := newMDInst(t)
	settings := scanSettings([]string{"md"}, "quarantine", map[string]any{"blockUntilScanned": true, "holdSeconds": 30})
	settings["proxy"] = map[string]any{"remoteUrl": upstream.URL}
	inst.CreateRepo("files-px", "raw", "proxy", settings)
	startWorkers(t, inst)

	if r := await(t, getAsync(inst, "/repository/files-px/dist/tool.tar.gz")); r.code != http.StatusOK || r.body != "tool release" {
		t.Fatalf("clean pull: %d %s", r.code, r.body)
	}
	r := await(t, getAsync(inst, "/repository/files-px/dist/evil.tar.gz"))
	if r.code != http.StatusForbidden || !strings.Contains(r.body, "in dist/evil.tar.gz › bin/payload.exe (dist/evil.tar.gz)") {
		t.Fatalf("infected pull: %d %s", r.code, r.body)
	}
}

// Files stored before scanning was enabled get components when it is
// switched on (in the background) or, at the latest, when downloaded.
func TestRawBackfill(t *testing.T) {
	inst, _ := newMDInst(t)
	inst.CreateRepo("files-old", "raw", "hosted", nil)
	for _, p := range []string{"a.txt", "dir/b.txt", "dir/sub/c.bin"} {
		putRaw(t, inst, "files-old", p, "content of "+p)
	}
	if n := countComponents(t, inst, "files-old"); n != 0 {
		t.Fatalf("components without scanning: %d", n)
	}
	inst.JSON("PUT", "/repositories/files-old", map[string]any{"name": "files-old", "format": "raw", "kind": "hosted",
		"blobStore": "default", "scan": map[string]any{"scanners": []string{"md"}, "mode": "quarantine", "blockUntilScanned": true,
			"holdSeconds": 30}}, http.StatusOK, nil)
	waitFor(t, func() bool { return countComponents(t, inst, "files-old") == 3 })
	rp, err := inst.App.Repos.Get(context.Background(), "files-old")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := inst.App.Scan.BackfillRaw(context.Background(), rp); err != nil || n != 0 {
		t.Fatalf("second backfill: %d %v", n, err)
	}

	// A file the backfill has not reached (unlinked here by hand) is linked
	// and scanned when it is downloaded.
	if _, err := inst.App.Pool.Exec(context.Background(), `UPDATE assets SET component_id = NULL WHERE path='a.txt'`); err != nil {
		t.Fatal(err)
	}
	startWorkers(t, inst)
	if r := await(t, getAsync(inst, "/repository/files-old/a.txt")); r.code != http.StatusOK || r.body != "content of a.txt" {
		t.Fatalf("lazy: %d %s", r.code, r.body)
	}
	c := findComponent(t, inst, "files-old", "a.txt", "")
	waitState(t, inst, c.ID, "clean")
}

// Scanners that look packages up by name (Trivy, Grype, webhooks) report
// raw files as unsupported, and policies for every format leave raw files
// alone; only policies for raw repositories remove them.
func TestRawFilesOtherScannersAndCleanup(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("files-tv", "raw", "hosted", scanSettings([]string{"trivy"}, "quarantine", map[string]any{"blockUntilScanned": true}))
	startWorkers(t, inst)
	putRaw(t, inst, "files-tv", "old.bin", "old")
	c := findComponent(t, inst, "files-tv", "old.bin", "")
	s := waitState(t, inst, c.ID, "unsupported")
	if !strings.Contains(s.Results[0].Error, "raw components cannot be scanned") {
		t.Fatalf("results: %+v", s.Results)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/files-tv/old.bin", testutil.BootstrapToken, nil), http.StatusOK)

	if _, err := inst.App.Pool.Exec(context.Background(), `UPDATE components SET created_at = now() - interval '40 days'`); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		Components []struct{ Name string } `json:"components"`
	}
	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "old-any", "criteria": map[string]any{"publishedOlderThanDays": 30}},
		http.StatusCreated, nil)
	inst.JSON("POST", "/cleanup-policies/old-any/preview?repository=files-tv", nil, http.StatusOK, &preview)
	if len(preview.Components) != 0 {
		t.Fatalf("policy for every format selects raw files: %+v", preview)
	}
	inst.JSON("POST", "/cleanup-policies", map[string]any{"name": "old-raw", "format": "raw",
		"criteria": map[string]any{"publishedOlderThanDays": 30}}, http.StatusCreated, nil)
	inst.JSON("POST", "/cleanup-policies/old-raw/preview?repository=files-tv", nil, http.StatusOK, &preview)
	if len(preview.Components) != 1 || preview.Components[0].Name != "old.bin" {
		t.Fatalf("raw policy: %+v", preview)
	}
}
