package scan_test

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/gitlab/gitlabtest"
	"github.com/entrepotproj/entrepot/internal/scan"
	"github.com/entrepotproj/entrepot/internal/testutil"
	"github.com/entrepotproj/entrepot/internal/testutil/oidctest"
)

// ---- helpers ---------------------------------------------------------------

func testdata(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newInst(t *testing.T, opts ...testutil.Option) *testutil.Instance {
	t.Helper()
	work := t.TempDir()
	opts = append([]testutil.Option{func(c *config.Config) {
		c.Scan.Workers = 2
		c.Scan.WorkDir = work
		c.Scan.PollInterval = 50 * time.Millisecond
	}}, opts...)
	inst := testutil.New(t, opts...)
	svc := inst.App.Scan
	svc.RetryBackoff = 50 * time.Millisecond
	svc.ReapEvery = time.Hour
	svc.RescanEvery = time.Hour
	t.Setenv("FAKE_SCAN_STATE", t.TempDir())
	t.Cleanup(func() {
		// Temporary scan inputs are removed.
		ents, _ := os.ReadDir(work)
		if len(ents) != 0 {
			t.Errorf("scan work dir not cleaned up: %v", ents)
		}
	})
	return inst
}

// startWorkers runs the pipeline until the test ends.
func startWorkers(t *testing.T, inst *testutil.Instance) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		inst.App.Scan.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func stateFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_SCAN_STATE"), name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func createTrivy(t *testing.T, inst *testutil.Instance, name string, extra map[string]any) {
	t.Helper()
	body := map[string]any{"name": name, "type": "trivy", "trivy": map[string]any{"binary": testdata(t, "fake-trivy.sh")}}
	for k, v := range extra {
		body[k] = v
	}
	inst.JSON("POST", "/scanners", body, http.StatusCreated, nil)
}

func scanSettings(scanners []string, mode string, extra map[string]any) map[string]any {
	s := map[string]any{"scanners": scanners, "mode": mode}
	for k, v := range extra {
		s[k] = v
	}
	return map[string]any{"scan": s}
}

func publishNPM(t *testing.T, inst *testutil.Instance, repoName, name, version, token string) string {
	t.Helper()
	content := []byte("tarball of " + name + "@" + version)
	data := base64.StdEncoding.EncodeToString(content)
	file := name + "-" + version + ".tgz"
	pkg := map[string]any{
		"name": name,
		"versions": map[string]any{version: map[string]any{"name": name, "version": version,
			"dist": map[string]any{"tarball": "http://x/" + name + "/-/" + file}}},
		"dist-tags":    map[string]string{"latest": version},
		"_attachments": map[string]any{file: map[string]any{"content_type": "application/octet-stream", "data": data, "length": len(content)}},
	}
	b, _ := json.Marshal(pkg)
	testutil.Expect(t, inst.Do("PUT", "/repository/"+repoName+"/"+name, token, strings.NewReader(string(b)),
		"Content-Type", "application/json"), http.StatusCreated)
	return "/repository/" + repoName + "/" + name + "/-/" + file
}

type component struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ScanState   string `json:"scanState"`
	Quarantined bool   `json:"quarantined"`
}

func findComponent(t *testing.T, inst *testutil.Instance, repoName, name, version string) component {
	t.Helper()
	var cs []component
	inst.JSON("GET", "/repositories/"+repoName+"/components?q="+name, nil, http.StatusOK, &cs)
	for _, c := range cs {
		if c.Name == name && c.Version == version {
			return c
		}
	}
	t.Fatalf("component %s@%s not found in %v", name, version, cs)
	return component{}
}

type scans struct {
	ScanState        string `json:"scanState"`
	Quarantined      bool   `json:"quarantined"`
	QuarantineReason string `json:"quarantineReason"`
	Results          []struct {
		Scanner  string         `json:"scanner"`
		Status   string         `json:"status"`
		Target   string         `json:"target"`
		Error    string         `json:"error"`
		Counts   map[string]int `json:"counts"`
		Findings []struct {
			VulnID   string `json:"vulnId"`
			Severity string `json:"severity"`
			Package  string `json:"package"`
			Waived   bool   `json:"waived"`
			WaiverID string `json:"waiverId"`
		} `json:"findings"`
	} `json:"results"`
	Jobs []struct {
		ID       string `json:"id"`
		Scanner  string `json:"scanner"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Attempts int    `json:"attempts"`
		Error    string `json:"error"`
	} `json:"jobs"`
}

func getScans(t *testing.T, inst *testutil.Instance, id string) scans {
	t.Helper()
	var s scans
	inst.JSON("GET", "/components/"+id+"/scans", nil, http.StatusOK, &s)
	return s
}

// storedState is the component's stored verdict (GET /components/{id}),
// which the download gate reads.
func storedState(t *testing.T, inst *testutil.Instance, id string) string {
	t.Helper()
	var d struct {
		Component component `json:"component"`
	}
	inst.JSON("GET", "/components/"+id, nil, http.StatusOK, &d)
	return d.Component.ScanState
}

// waitState waits until the component reaches state with no outstanding jobs,
// both in the verdict computed from the latest results (/scans) and in the
// stored copy the download gate reads. The worker stores a result before it
// stores the verdict, so for a moment the first can be ahead of the second.
func waitState(t *testing.T, inst *testutil.Instance, id, state string) scans {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var s scans
	stored := ""
	for time.Now().Before(deadline) {
		s = getScans(t, inst, id)
		busy := false
		for _, j := range s.Jobs {
			if j.Status == "queued" || j.Status == "running" {
				busy = true
			}
		}
		if s.ScanState == state && !busy {
			if stored = storedState(t, inst, id); stored == state {
				return s
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("component %s did not reach %s (stored: %q): %+v", id, state, stored, s)
	return s
}

// ---- tests -----------------------------------------------------------------

// Upload -> job -> findings -> quarantine 403 -> waiver -> download allowed.
func TestUploadQuarantineAndWaiver(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("npm-libs", "npm", "hosted", scanSettings([]string{"trivy"}, "quarantine", nil))
	startWorkers(t, inst)

	tarball := publishNPM(t, inst, "npm-libs", "lodash", "4.17.20", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-libs", "lodash", "4.17.20")
	s := waitState(t, inst, c.ID, "vulnerable")
	if !s.Quarantined || !strings.Contains(s.QuarantineReason, "CVE-2021-23337 (high) in lodash@4.17.20") {
		t.Fatalf("not quarantined: %+v", s)
	}
	if len(s.Results) != 1 || s.Results[0].Status != "ok" || s.Results[0].Target != "pkg:npm/lodash@4.17.20" ||
		len(s.Results[0].Findings) != 4 || s.Results[0].Counts["high"] != 2 || s.Results[0].Counts["medium"] != 2 {
		t.Fatalf("results: %+v", s.Results)
	}
	if len(s.Jobs) != 1 || s.Jobs[0].Status != "done" || s.Jobs[0].Reason != "upload" || s.Jobs[0].Attempts != 1 {
		t.Fatalf("jobs: %+v", s.Jobs)
	}

	resp := inst.Do("GET", tarball, testutil.BootstrapToken, nil)
	body := testutil.Expect(t, resp, http.StatusForbidden)
	if !strings.Contains(body, "CVE-2021-23337 (high) in lodash@4.17.20") || !strings.Contains(body, "and 1 more") ||
		resp.Header.Get("X-Entrepot-Quarantined") != "true" {
		t.Fatalf("quarantine response: %s", body)
	}
	// The packument (metadata) is not blocked.
	testutil.Expect(t, inst.Do("GET", "/repository/npm-libs/lodash", testutil.BootstrapToken, nil), http.StatusOK)

	// Waive one high finding: still quarantined by the other.
	var w1 struct{ ID string }
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "CVE-2021-23337", "componentPattern": "lodash@4.17.*",
		"reason": "template() not used"}, http.StatusCreated, &w1)
	body = testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "CVE-2026-4800") {
		t.Fatalf("expected the remaining finding in %s", body)
	}
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "CVE-2026-4800", "repositoryPattern": "npm-*",
		"componentPattern": "lodash"}, http.StatusCreated, nil)
	testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusOK)
	s = getScans(t, inst, c.ID)
	waived := 0
	for _, f := range s.Results[0].Findings {
		if f.Waived {
			waived++
		}
	}
	if s.Quarantined || s.ScanState != "vulnerable" || waived != 2 || s.Results[0].Counts["high"] != 0 {
		t.Fatalf("after waivers: %+v", s)
	}
	// Deleting a waiver re-quarantines.
	inst.JSON("DELETE", "/waivers/"+w1.ID, nil, http.StatusNoContent, nil)
	testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusForbidden)

	// A clean package passes.
	clean := publishNPM(t, inst, "npm-libs", "left-pad", "1.3.0", testutil.BootstrapToken)
	c2 := findComponent(t, inst, "npm-libs", "left-pad", "1.3.0")
	waitState(t, inst, c2.ID, "clean")
	testutil.Expect(t, inst.Do("GET", clean, testutil.BootstrapToken, nil), http.StatusOK)

	// Manual rescan (write permission) returns the queued job.
	var jobs []struct{ ID, Status, Reason, Scanner string }
	inst.JSON("POST", "/components/"+c2.ID+"/scan", nil, http.StatusAccepted, &jobs)
	if len(jobs) != 1 || jobs[0].Reason != "manual" || jobs[0].Scanner != "trivy" {
		t.Fatalf("manual scan jobs: %+v", jobs)
	}
	reader := inst.Token("reader", "viewer", "*")
	testutil.Expect(t, inst.Do("POST", "/api/v1/components/"+c2.ID+"/scan", reader, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("GET", "/api/v1/components/"+c2.ID+"/scans", reader, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/api/v1/scan-jobs", reader, nil), http.StatusForbidden)
	var all []map[string]any
	inst.JSON("GET", "/scan-jobs?status=done&limit=10", nil, http.StatusOK, &all)
	if len(all) < 2 {
		t.Fatalf("scan jobs: %v", all)
	}
	// The API asset download is gated too.
	var detail struct {
		Assets []struct{ ID string } `json:"assets"`
	}
	inst.JSON("GET", "/components/"+c.ID, nil, http.StatusOK, &detail)
	testutil.Expect(t, inst.Do("GET", "/api/v1/assets/"+detail.Assets[0].ID+"/content", testutil.BootstrapToken, nil), http.StatusForbidden)
}

// Search filters by scan state and quarantine, and summarises unwaived findings.
func TestSearchBySecurityState(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("npm-libs", "npm", "hosted", scanSettings([]string{"trivy"}, "quarantine", nil))
	startWorkers(t, inst)

	publishNPM(t, inst, "npm-libs", "lodash", "4.17.20", testutil.BootstrapToken)
	publishNPM(t, inst, "npm-libs", "left-pad", "1.3.0", testutil.BootstrapToken)
	waitState(t, inst, findComponent(t, inst, "npm-libs", "lodash", "4.17.20").ID, "vulnerable")
	waitState(t, inst, findComponent(t, inst, "npm-libs", "left-pad", "1.3.0").ID, "clean")

	type result struct {
		Name          string         `json:"name"`
		FindingCounts map[string]int `json:"findingCounts"`
		Findings      []struct {
			VulnID   string `json:"vulnId"`
			Severity string `json:"severity"`
			URL      string `json:"url"`
		} `json:"findings"`
	}
	search := func(query string) []result {
		t.Helper()
		var out []result
		inst.JSON("GET", "/search?"+query, nil, http.StatusOK, &out)
		return out
	}

	// The stored state trails the live verdict by a moment; wait for it.
	for _, q := range []string{"scanState=vulnerable", "scanState=clean"} {
		deadline := time.Now().Add(10 * time.Second)
		for len(search(q)) == 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
	}

	if r := search("scanState=vulnerable"); len(r) != 1 || r[0].Name != "lodash" || r[0].Findings != nil || r[0].FindingCounts != nil {
		t.Fatalf("vulnerable without findings: %+v", r)
	}
	if r := search("scanState=clean"); len(r) != 1 || r[0].Name != "left-pad" {
		t.Fatalf("clean: %+v", r)
	}
	if r := search("quarantined=true"); len(r) != 1 || r[0].Name != "lodash" {
		t.Fatalf("quarantined: %+v", r)
	}
	if r := search("quarantined=false"); len(r) != 1 || r[0].Name != "left-pad" {
		t.Fatalf("not quarantined: %+v", r)
	}
	testutil.Expect(t, inst.Do("GET", "/api/v1/search?scanState=bogus", testutil.BootstrapToken, nil), http.StatusBadRequest)

	r := search("scanState=vulnerable&withFindings=true")
	if len(r) != 1 || r[0].FindingCounts["high"] != 2 || r[0].FindingCounts["medium"] != 2 || len(r[0].Findings) != 4 {
		t.Fatalf("with findings: %+v", r)
	}
	for i, f := range r[0].Findings {
		if i < 2 && f.Severity != "high" || i >= 2 && f.Severity != "medium" {
			t.Fatalf("findings not ordered by severity: %+v", r[0].Findings)
		}
	}

	// A waived finding drops out of both the counts and the list.
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "CVE-2021-23337", "componentPattern": "lodash@4.17.*",
		"reason": "template() not used"}, http.StatusCreated, nil)
	r = search("scanState=vulnerable&withFindings=true")
	if len(r) != 1 || r[0].FindingCounts["high"] != 1 || len(r[0].Findings) != 3 {
		t.Fatalf("after waiver: %+v", r)
	}
	for _, f := range r[0].Findings {
		if f.VulnID == "CVE-2021-23337" {
			t.Fatalf("waived finding listed: %+v", r[0].Findings)
		}
	}

	// Components the caller cannot read are never listed.
	if r := search("scanState=vulnerable&repository=nope"); len(r) != 0 {
		t.Fatalf("unknown repository: %+v", r)
	}
}

// Warn mode records findings but never blocks; grype output is parsed.
func TestWarnModeNeverBlocks(t *testing.T) {
	inst := newInst(t)
	inst.JSON("POST", "/scanners", map[string]any{"name": "grype", "type": "grype",
		"grype": map[string]any{"binary": testdata(t, "fake-grype.sh")}}, http.StatusCreated, nil)
	inst.CreateRepo("npm-warn", "npm", "hosted", scanSettings([]string{"grype"}, "warn", map[string]any{"severityThreshold": "low"}))
	startWorkers(t, inst)
	tarball := publishNPM(t, inst, "npm-warn", "lodash", "4.17.20", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-warn", "lodash", "4.17.20")
	s := waitState(t, inst, c.ID, "vulnerable")
	if s.Quarantined || len(s.Results) != 1 || len(s.Results[0].Findings) != 3 || s.Results[0].Findings[0].VulnID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("scans: %+v", s)
	}
	testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusOK)

	// Switching the repository to quarantine blocks without a rescan.
	inst.JSON("PUT", "/repositories/npm-warn", map[string]any{"name": "npm-warn", "format": "npm", "kind": "hosted",
		"blobStore": "default", "scan": map[string]any{"scanners": []string{"grype"}, "mode": "quarantine", "severityThreshold": "high"}},
		http.StatusOK, nil)
	inst.App.Repos.Invalidate("npm-warn")
	body := testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "GHSA-35jh-r3h4-6jhm (high)") {
		t.Fatalf("body: %s", body)
	}
}

// blockUntilScanned blocks downloads until the first scan completes.
func TestBlockUntilScanned(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("npm-strict", "npm", "hosted", scanSettings([]string{"trivy"}, "quarantine",
		map[string]any{"blockUntilScanned": true}))
	tarball := publishNPM(t, inst, "npm-strict", "left-pad", "1.3.0", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-strict", "left-pad", "1.3.0")
	if c.ScanState != "pending" {
		t.Fatalf("state = %s, want pending", c.ScanState)
	}
	body := testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "has not been scanned yet") {
		t.Fatalf("body: %s", body)
	}
	startWorkers(t, inst)
	waitState(t, inst, c.ID, "clean")
	testutil.Expect(t, inst.Do("GET", tarball, testutil.BootstrapToken, nil), http.StatusOK)

	// Without blockUntilScanned, unscanned content is served.
	inst.CreateRepo("npm-lax", "npm", "hosted", scanSettings([]string{"trivy"}, "quarantine", nil))
	stateFile(t, "fail", "100")
	tb2 := publishNPM(t, inst, "npm-lax", "left-pad", "1.3.0", testutil.BootstrapToken)
	testutil.Expect(t, inst.Do("GET", tb2, testutil.BootstrapToken, nil), http.StatusOK)
}

// Failed scans are retried with backoff, then fail; expired leases are
// reclaimed; heartbeats keep long scans alive.
func TestRetriesAndLeases(t *testing.T) {
	inst := newInst(t)
	svc := inst.App.Scan
	// Heartbeats every Lease/3 keep longer scans alive (checked below).
	svc.Lease = 600 * time.Millisecond
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("npm-r", "npm", "hosted", scanSettings([]string{"trivy"}, "warn", nil))
	stateFile(t, "fail", "2")
	startWorkers(t, inst)

	publishNPM(t, inst, "npm-r", "lodash", "4.17.20", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-r", "lodash", "4.17.20")
	s := waitState(t, inst, c.ID, "vulnerable")
	if s.Jobs[0].Attempts != 3 || s.Jobs[0].Status != "done" {
		t.Fatalf("expected success on the third attempt: %+v", s.Jobs)
	}

	// Always failing: job fails after MaxAttempts and the component is in error.
	stateFile(t, "fail", "100")
	publishNPM(t, inst, "npm-r", "left-pad", "1.3.0", testutil.BootstrapToken)
	c2 := findComponent(t, inst, "npm-r", "left-pad", "1.3.0")
	s = waitState(t, inst, c2.ID, "error")
	if s.Jobs[0].Status != "failed" || s.Jobs[0].Attempts != 3 || !strings.Contains(s.Jobs[0].Error, "simulated failure") ||
		s.Results[0].Status != "error" || !strings.Contains(s.Results[0].Error, "simulated failure") {
		t.Fatalf("failed job: %+v", s)
	}
	stateFile(t, "fail", "0")

	// Lease expiry: a job held by a dead worker is reclaimed.
	ctx := context.Background()
	inst.JSON("POST", "/components/"+c2.ID+"/scan", nil, http.StatusAccepted, nil)
	pool := inst.App.Pool
	// Wait for the job to complete normally, then simulate a crashed worker.
	waitState(t, inst, c2.ID, "clean")
	var jobID string
	if err := pool.QueryRow(ctx, `INSERT INTO scan_jobs (component_id, scanner_id, status, attempts, locked_by, locked_until, reason)
		SELECT $1, id, 'running', 1, 'dead-worker', now() - interval '1 minute', 'manual' FROM scanners WHERE name='trivy'
		RETURNING id`, c2.ID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	n, err := svc.ReapNow(ctx)
	if err != nil || n != 1 {
		t.Fatalf("reap: %d %v", n, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var status, errMsg string
		var attempts int
		_ = pool.QueryRow(ctx, `SELECT status, error, attempts FROM scan_jobs WHERE id=$1`, jobID).Scan(&status, &errMsg, &attempts)
		if status == "done" && attempts == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reclaimed job: %s %s %d", status, errMsg, attempts)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// An expired job that used all attempts fails with an error result.
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (component_id, scanner_id, status, attempts, locked_by, locked_until, reason)
		SELECT $1, id, 'running', 3, 'webhook', now() - interval '1 second', 'manual' FROM scanners WHERE name='trivy'`, c2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReapNow(ctx); err != nil {
		t.Fatal(err)
	}
	s = getScans(t, inst, c2.ID)
	if s.ScanState != "error" || !strings.Contains(s.Results[0].Error, "did not report results in time") {
		t.Fatalf("after expiry: %+v", s)
	}

	// Heartbeat: a scan longer than the lease completes on the first attempt
	// while the reaper runs.
	t.Setenv("FAKE_SCAN_SLEEP", "2")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				_, _ = svc.ReapNow(ctx)
			}
		}
	}()
	var jobs []struct{ ID string }
	inst.JSON("POST", "/components/"+c.ID+"/scan", nil, http.StatusAccepted, &jobs)
	deadline = time.Now().Add(15 * time.Second)
	for {
		var status string
		var attempts int
		_ = pool.QueryRow(ctx, `SELECT status, attempts FROM scan_jobs WHERE id=$1`, jobs[0].ID).Scan(&status, &attempts)
		if status == "done" {
			if attempts != 1 {
				t.Fatalf("long scan was reclaimed: attempts=%d", attempts)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("long scan did not finish: %s", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// Rescans are scheduled for results older than rescanIntervalHours.
func TestRescanScheduling(t *testing.T) {
	inst := newInst(t)
	createTrivy(t, inst, "trivy", map[string]any{"rescanIntervalHours": 24})
	createTrivy(t, inst, "trivy-norescan", nil)
	inst.CreateRepo("npm-s", "npm", "hosted", scanSettings([]string{"trivy", "trivy-norescan"}, "warn", nil))
	startWorkers(t, inst)
	publishNPM(t, inst, "npm-s", "lodash", "4.17.20", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-s", "lodash", "4.17.20")
	waitState(t, inst, c.ID, "vulnerable")
	ctx := context.Background()
	if n, err := inst.App.Scan.RescanNow(ctx); err != nil || n != 0 {
		t.Fatalf("fresh results rescanned: %d %v", n, err)
	}
	if _, err := inst.App.Pool.Exec(ctx, `UPDATE scan_results SET scanned_at = now() - interval '25 hours'`); err != nil {
		t.Fatal(err)
	}
	if n, err := inst.App.Scan.RescanNow(ctx); err != nil || n != 1 {
		t.Fatalf("rescan: %d %v", n, err)
	}
	s := waitState(t, inst, c.ID, "vulnerable")
	var reasons []string
	for _, j := range s.Jobs {
		reasons = append(reasons, j.Scanner+":"+j.Reason)
	}
	if len(s.Jobs) != 3 || !strings.Contains(strings.Join(reasons, ","), "trivy:rescan") {
		t.Fatalf("jobs: %v", reasons)
	}
	var results int
	_ = inst.App.Pool.QueryRow(ctx, `SELECT count(*) FROM scan_results`).Scan(&results)
	if results != 3 {
		t.Fatalf("results = %d", results)
	}
}

// Scanner configuration API: secrets sealed and never returned, delete
// refused while referenced, test endpoint.
func TestScannerAPI(t *testing.T) {
	var pings []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get(scan.SignatureHeader) != scan.Sign("hook-secret", b) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		pings = append(pings, string(b))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hook.Close()
	inst := newInst(t)
	createTrivy(t, inst, "trivy", map[string]any{"trivy": map[string]any{"binary": testdata(t, "fake-trivy.sh"),
		"serverUrl": hook.URL + "/trivy", "serverToken": "trivy-token-123", "extraArgs": []string{"--offline-scan"}}})
	inst.JSON("POST", "/scanners", map[string]any{"name": "hook", "type": "webhook", "rescanIntervalHours": 12,
		"webhook": map[string]any{"url": hook.URL, "secret": "hook-secret", "timeoutSeconds": 60}}, http.StatusCreated, nil)
	inst.JSON("POST", "/scanners", map[string]any{"name": "bad", "type": "webhook"}, http.StatusBadRequest, nil)
	inst.JSON("POST", "/scanners", map[string]any{"name": "Bad Name", "type": "trivy"}, http.StatusBadRequest, nil)
	inst.JSON("POST", "/scanners", map[string]any{"name": "hook", "type": "grype"}, http.StatusConflict, nil)

	var list []map[string]any
	inst.JSON("GET", "/scanners", nil, http.StatusOK, &list)
	raw, _ := json.Marshal(list)
	if len(list) != 2 || strings.Contains(string(raw), "trivy-token-123") || strings.Contains(string(raw), "hook-secret") ||
		strings.Contains(string(raw), "enc:v1") || !strings.Contains(string(raw), `"rescanIntervalHours":12`) {
		t.Fatalf("scanners: %s", raw)
	}
	var stored string
	_ = inst.App.Pool.QueryRow(context.Background(), `SELECT config::text FROM scanners WHERE name='hook'`).Scan(&stored)
	if strings.Contains(stored, "hook-secret") || !strings.Contains(stored, "enc:v1:") {
		t.Fatalf("secret not sealed: %s", stored)
	}
	// Webhook ping is signed; an update without the secret keeps it.
	inst.JSON("PUT", "/scanners/hook", map[string]any{"name": "hook", "type": "webhook", "enabled": true,
		"webhook": map[string]any{"url": hook.URL}}, http.StatusOK, nil)
	var res struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
		Version string `json:"version"`
	}
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if !res.OK || len(pings) != 1 || !strings.Contains(pings[0], `"type":"ping"`) {
		t.Fatalf("ping: %+v %v", res, pings)
	}
	// Test block: version read from the endpoint's JSON reply.
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"role":"ingress","version":"r2-41e818e41df7"}`))
		case "/text":
			_, _ = w.Write([]byte("ok"))
		default:
			http.Error(w, "nope", http.StatusServiceUnavailable)
		}
	}))
	defer status.Close()
	put := func(test map[string]any) {
		inst.JSON("PUT", "/scanners/hook", map[string]any{"name": "hook", "type": "webhook", "enabled": true,
			"webhook": map[string]any{"url": hook.URL, "test": test}}, http.StatusOK, nil)
	}
	put(map[string]any{"url": status.URL + "/status", "versionPath": "$.version"})
	res.Version = ""
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if !res.OK || res.Version != "r2-41e818e41df7" || len(pings) != 1 {
		t.Fatalf("test endpoint: %+v", res)
	}
	put(map[string]any{"url": status.URL + "/status?token=s3cret", "versionPath": "$.nope"})
	res.Version = ""
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if res.OK || res.Version != "" || strings.Contains(res.Message, "s3cret") {
		t.Fatalf("missing path: %+v", res)
	}
	put(map[string]any{"url": status.URL + "/text", "versionPath": "$.version"})
	res.Version = ""
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if res.OK || !strings.Contains(res.Message, "not JSON") {
		t.Fatalf("non-JSON: %+v", res)
	}
	put(map[string]any{"url": status.URL + "/down?token=s3cret", "versionPath": "$.version"})
	res.Version = ""
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if res.OK || !strings.Contains(res.Message, "503") || strings.Contains(res.Message, "s3cret") {
		t.Fatalf("bad status: %+v", res)
	}
	put(map[string]any{"url": status.URL + "/down", "expectedStatus": 503})
	res.Version = ""
	inst.JSON("POST", "/scanners/hook/test", nil, http.StatusOK, &res)
	if !res.OK {
		t.Fatalf("expected status: %+v", res)
	}
	// Trivy: version, and the (fake) server's /healthz is checked.
	inst.JSON("POST", "/scanners/trivy/test", nil, http.StatusOK, &res)
	if res.Version != "0.99.0-fake" || res.OK || !strings.Contains(res.Message, "healthz answered") {
		t.Fatalf("trivy test: %+v", res)
	}
	inst.JSON("PUT", "/scanners/trivy", map[string]any{"name": "trivy", "type": "trivy",
		"trivy": map[string]any{"binary": testdata(t, "fake-trivy.sh")}}, http.StatusOK, nil)
	inst.JSON("POST", "/scanners/trivy/test", nil, http.StatusOK, &res)
	if !res.OK || !strings.Contains(res.Message, "trivy 0.99.0-fake, vulnerability DB v2") {
		t.Fatalf("trivy test: %+v", res)
	}
	inst.JSON("PUT", "/scanners/trivy", map[string]any{"name": "trivy", "type": "trivy",
		"trivy": map[string]any{"binary": "/nonexistent/trivy"}}, http.StatusOK, nil)
	inst.JSON("POST", "/scanners/trivy/test", nil, http.StatusOK, &res)
	if res.OK {
		t.Fatalf("missing binary reported ok: %+v", res)
	}

	inst.CreateRepo("uses-hook", "npm", "hosted", scanSettings([]string{"hook"}, "warn", nil))
	inst.JSON("DELETE", "/scanners/hook", nil, http.StatusConflict, nil)
	inst.JSON("DELETE", "/scanners/trivy", nil, http.StatusNoContent, nil)
	inst.JSON("GET", "/scanners/trivy", nil, http.StatusNotFound, nil)
	reader := inst.Token("reader", "viewer", "*")
	testutil.Expect(t, inst.Do("GET", "/api/v1/scanners", reader, nil), http.StatusForbidden)

	// Waivers: admin only, createdBy recorded, validation.
	var wv map[string]any
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "CVE-1", "expiresAt": time.Now().Add(time.Hour)}, http.StatusCreated, &wv)
	if wv["createdBy"] != "bootstrap-admin" || wv["componentPattern"] != "*" || wv["repositoryPattern"] != "*" {
		t.Fatalf("waiver: %v", wv)
	}
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "*"}, http.StatusBadRequest, nil)
	inst.JSON("PUT", "/waivers/"+wv["id"].(string), map[string]any{"vulnId": "CVE-2", "reason": "r"}, http.StatusOK, &wv)
	if wv["vulnId"] != "CVE-2" {
		t.Fatalf("update: %v", wv)
	}
	inst.JSON("GET", "/waivers/not-a-uuid", nil, http.StatusNotFound, nil)
	testutil.Expect(t, inst.Do("GET", "/api/v1/waivers", reader, nil), http.StatusForbidden)
	var audit int
	_ = inst.App.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action LIKE 'scanner.%' OR action LIKE 'waiver.%'`).Scan(&audit)
	if audit < 6 {
		t.Fatalf("audit events = %d", audit)
	}
}

// fakeWebhook is a webhook scanner that fetches the artifact and calls
// back with a report built by respond.
type fakeWebhook struct {
	*httptest.Server
	t       *testing.T
	secret  string
	mu      sync.Mutex
	reqs    []scan.WebhookRequest
	art     map[string][]byte
	respond func(req scan.WebhookRequest) any
}

func newFakeWebhook(t *testing.T, secret string, respond func(req scan.WebhookRequest) any) *fakeWebhook {
	f := &fakeWebhook{t: t, secret: secret, respond: respond, art: map[string][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get(scan.SignatureHeader) != scan.Sign(secret, b) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var req scan.WebhookRequest
		_ = json.Unmarshal(b, &req)
		f.mu.Lock()
		f.reqs = append(f.reqs, req)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		if req.Type != "scan" {
			return
		}
		go f.work(req)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWebhook) work(req scan.WebhookRequest) {
	resp, err := http.Get(req.ArtifactURL)
	if err != nil {
		f.t.Errorf("fetch artifact: %v", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		f.t.Errorf("artifact: %d %s", resp.StatusCode, b)
		return
	}
	f.mu.Lock()
	f.art[req.JobID] = b
	f.mu.Unlock()
	body, _ := json.Marshal(f.respond(req))
	cb, _ := http.NewRequest("POST", req.CallbackURL, strings.NewReader(string(body)))
	cb.Header.Set("Authorization", "Bearer "+req.Token)
	cb.Header.Set("Content-Type", "application/json")
	cresp, err := http.DefaultClient.Do(cb)
	if err != nil {
		f.t.Errorf("callback: %v", err)
		return
	}
	cbody, _ := io.ReadAll(cresp.Body)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusNoContent {
		f.t.Errorf("callback status %d: %s", cresp.StatusCode, cbody)
	}
}

// Webhook scanners: signed request, artifact download with the job token,
// SARIF / CycloneDX / native / unsupported callbacks.
func TestWebhookScanner(t *testing.T) {
	sarif, _ := os.ReadFile(testdata(t, "trivy-lodash.sarif.json"))
	cdx, _ := os.ReadFile(testdata(t, "trivy-lodash.cdx.json"))
	hook := newFakeWebhook(t, "s3cret", func(req scan.WebhookRequest) any {
		switch req.Component.Name {
		case "lodash":
			return map[string]any{"format": "sarif", "document": json.RawMessage(sarif)}
		case "lodash-cdx":
			return map[string]any{"format": "cyclonedx", "document": json.RawMessage(cdx)}
		case "native":
			return map[string]any{"findings": []map[string]any{{"vulnId": "CVE-2099-1", "severity": "Critical", "package": "native",
				"installedVersion": "1.0.0", "extra": "ignored"}}}
		case "unsupported":
			return map[string]any{"unsupported": true}
		default:
			return map[string]any{"findings": []any{}}
		}
	})
	inst := newInst(t)
	inst.JSON("POST", "/scanners", map[string]any{"name": "hook", "type": "webhook",
		"webhook": map[string]any{"url": hook.URL, "secret": "s3cret"}}, http.StatusCreated, nil)
	inst.CreateRepo("npm-h", "npm", "hosted", scanSettings([]string{"hook"}, "quarantine", nil))
	startWorkers(t, inst)

	publishNPM(t, inst, "npm-h", "lodash", "4.17.20", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-h", "lodash", "4.17.20")
	s := waitState(t, inst, c.ID, "vulnerable")
	if !s.Quarantined || len(s.Results[0].Findings) != 4 || s.Results[0].Target != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("sarif: %+v", s)
	}
	hook.mu.Lock()
	req := hook.reqs[0]
	art := string(hook.art[req.JobID])
	hook.mu.Unlock()
	if req.Type != "scan" || req.Repository != "npm-h" || req.Component.PURL != "pkg:npm/lodash@4.17.20" || req.Target != "package" ||
		!strings.HasPrefix(req.Token, "esj_") || !strings.HasPrefix(req.CallbackURL, inst.URL+"/api/v1/scan-jobs/") {
		t.Fatalf("request: %+v", req)
	}
	if art != "tarball of lodash@4.17.20" {
		t.Fatalf("artifact = %q", art)
	}
	// Only the token hash is stored; the token no longer works once done.
	var hashed bool
	_ = inst.App.Pool.QueryRow(context.Background(), `SELECT token_hash IS NOT NULL FROM scan_jobs WHERE id=$1`, req.JobID).Scan(&hashed)
	if hashed {
		t.Fatal("token hash kept after completion")
	}
	testutil.Expect(t, inst.Do("GET", "/api/v1/scan-jobs/"+req.JobID+"/artifact?token="+req.Token, "", nil), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("POST", "/api/v1/scan-jobs/"+req.JobID+"/result", req.Token, strings.NewReader(`{}`)), http.StatusUnauthorized)

	for name, want := range map[string]string{"lodash-cdx": "vulnerable", "native": "vulnerable", "unsupported": "unsupported", "empty": "clean"} {
		publishNPM(t, inst, "npm-h", name, "1.0.0", testutil.BootstrapToken)
		c := findComponent(t, inst, "npm-h", name, "1.0.0")
		s := waitState(t, inst, c.ID, want)
		switch name {
		case "lodash-cdx":
			if len(s.Results[0].Findings) != 4 || !s.Quarantined {
				t.Errorf("cyclonedx: %+v", s)
			}
		case "native":
			if s.Results[0].Findings[0].Severity != "critical" || !s.Quarantined {
				t.Errorf("native: %+v", s)
			}
		}
	}
}

// Webhook jobs that never call back fail after their deadline.
func TestWebhookTimeout(t *testing.T) {
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer silent.Close()
	inst := newInst(t)
	inst.App.Scan.MaxAttempts = 1
	inst.JSON("POST", "/scanners", map[string]any{"name": "silent", "type": "webhook",
		"webhook": map[string]any{"url": silent.URL, "timeoutSeconds": 1}}, http.StatusCreated, nil)
	inst.CreateRepo("npm-t", "npm", "hosted", scanSettings([]string{"silent"}, "warn", nil))
	startWorkers(t, inst)
	publishNPM(t, inst, "npm-t", "x", "1.0.0", testutil.BootstrapToken)
	c := findComponent(t, inst, "npm-t", "x", "1.0.0")
	time.Sleep(1500 * time.Millisecond)
	if _, err := inst.App.Scan.ReapNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := waitState(t, inst, c.ID, "error")
	if s.Jobs[0].Status != "failed" {
		t.Fatalf("jobs: %+v", s.Jobs)
	}
}

// GitLab feedback: commit status and one MR note per repository/component,
// updated (not duplicated) by later scans.
func TestGitLabFeedback(t *testing.T) {
	gl := oidctest.New(t)
	api := gitlabtest.New(t, "glpat-test")
	api.AddMergeRequest("77", "abc123", 5)
	inst := newInst(t, func(c *config.Config) {
		c.Auth.GitLab = []config.GitLabSpec{{Name: "gitlab", IssuerURL: gl.URL,
			API: config.GitLabAPI{URL: api.URL, Token: "glpat-test"}}}
	})
	createTrivy(t, inst, "trivy", nil)
	inst.CreateRepo("npm-ci", "npm", "hosted", scanSettings([]string{"trivy"}, "quarantine", nil))
	inst.JSON("POST", "/gitlab-trust-policies", map[string]any{
		"name": "all", "gitlab": "gitlab", "conditions": map[string]string{"project_path": "**"},
	}, http.StatusCreated, nil)
	inst.JSON("POST", "/role-bindings", map[string]any{"role": "developer", "subjectType": "gitlab_policy", "subject": "all"}, http.StatusCreated, nil)
	tok := gl.Mint(t, map[string]any{"aud": inst.URL, "project_path": "team/app", "project_id": "77", "ref": "feature",
		"sha": "abc123", "pipeline_id": "9", "job_id": "42"}, time.Minute)
	startWorkers(t, inst)

	publishNPM(t, inst, "npm-ci", "lodash", "4.17.20", tok)
	c := findComponent(t, inst, "npm-ci", "lodash", "4.17.20")
	waitState(t, inst, c.ID, "vulnerable")
	waitFor(t, func() bool { return len(api.Notes(5)) == 1 })
	st := api.Statuses()
	last := st[len(st)-1]
	if last.Project != "77" || last.SHA != "abc123" || last.Status.State != "failed" || last.Status.Name != "entrepot/scan/npm-ci" ||
		last.Status.TargetURL != inst.URL+"/components/"+c.ID || last.Status.PipelineID != 9 || last.Status.Ref != "feature" ||
		!strings.Contains(last.Status.Description, "2 high, 2 medium") {
		t.Fatalf("status: %+v", last)
	}
	note := api.Notes(5)[0]
	if !strings.Contains(note, "<!-- entrepot-scan:npm-ci:lodash@4.17.20 -->") || !strings.Contains(note, "| high | [CVE-2021-23337]") ||
		!strings.Contains(note, "quarantined") {
		t.Fatalf("note: %s", note)
	}
	// Waive everything for lodash and rescan: the note is updated in place.
	inst.JSON("POST", "/waivers", map[string]any{"vulnId": "*", "componentPattern": "lodash"}, http.StatusCreated, nil)
	inst.JSON("POST", "/components/"+c.ID+"/scan", nil, http.StatusAccepted, nil)
	waitFor(t, func() bool {
		ns := api.Notes(5)
		return len(ns) == 1 && strings.Contains(ns[0], "~~high~~ (waived)")
	})
	waitFor(t, func() bool {
		st := api.Statuses()
		return st[len(st)-1].Status.State == "success"
	})
	if api.Creates != 1 || api.Updates < 1 {
		t.Fatalf("creates=%d updates=%d", api.Creates, api.Updates)
	}
	// Uploads by other principals do not report.
	n := len(api.Statuses())
	publishNPM(t, inst, "npm-ci", "left-pad", "1.3.0", testutil.BootstrapToken)
	c2 := findComponent(t, inst, "npm-ci", "left-pad", "1.3.0")
	waitState(t, inst, c2.ID, "clean")
	inst.App.Scan.FeedbackWait()
	if len(api.Statuses()) != n {
		t.Fatalf("unexpected status for a non-CI upload")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// untar extracts a tar into a map.
func untar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(strings.NewReader(string(b)))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		c, _ := io.ReadAll(tr)
		out[h.Name] = c
	}
}

func TestExtractJSONString(t *testing.T) {
	doc := []byte(`{"version":"1.2","n":7,"items":[{"v":"a"},{"v":"b"}],"o":{"x":null}}`)
	for path, want := range map[string]string{"$.version": "1.2", ".version": "1.2", "$.n": "7", "$.items[1].v": "b"} {
		if got, err := scan.ExtractJSONString(doc, path); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	long, _ := json.Marshal(map[string]string{"v": strings.Repeat("é", 500), "c": "1.0\x1b[31m", "n": "1.0\nX", "e": "  "})
	if got, err := scan.ExtractJSONString(long, "$.v"); err != nil || len([]rune(got)) != scan.MaxVersionLen+1 || !strings.HasSuffix(got, "…") {
		t.Errorf("long version = %d runes, %v", len([]rune(got)), err)
	}
	for _, path := range []string{"$.c", "$.n", "$.e"} {
		if got, err := scan.ExtractJSONString(long, path); err == nil {
			t.Errorf("%s = %q, want error", path, got)
		}
	}
	for _, path := range []string{"$.missing", "$.items[5].v", "$.items", "$.o.x", "$.version.x", "$[", "$version"} {
		if got, err := scan.ExtractJSONString(doc, path); err == nil {
			t.Errorf("%s = %q, want error", path, got)
		}
	}
}
