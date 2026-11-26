package scan_test

import (
	"archive/zip"
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/scan"
	"github.com/entrepotproj/entrepot/internal/testutil"
)

func cleanReport(scan.WebhookRequest) any { return map[string]any{"findings": []any{}} }

// releaser blocks webhook reports until released (once, also at cleanup).
type releaser struct {
	ch   chan struct{}
	once sync.Once
}

func newReleaser(t *testing.T) *releaser {
	r := &releaser{ch: make(chan struct{})}
	t.Cleanup(r.release)
	return r
}

func (r *releaser) release() { r.once.Do(func() { close(r.ch) }) }

func createHook(t *testing.T, inst *testutil.Instance, name string, hook *fakeWebhook) {
	t.Helper()
	inst.JSON("POST", "/scanners", map[string]any{"name": name, "type": "webhook",
		"webhook": map[string]any{"url": hook.URL, "secret": hook.secret}}, http.StatusCreated, nil)
}

func hasResult(t *testing.T, inst *testutil.Instance, id, scanner string) bool {
	for _, r := range getScans(t, inst, id).Results {
		if r.Scanner == scanner {
			return true
		}
	}
	return false
}

// Strict verdicts (blockOnError) wait for every configured scanner; other
// repositories keep the original rule where the first completed scan decides.
func TestStrictVerdictWaitsForEveryScanner(t *testing.T) {
	gate := newReleaser(t)
	slow := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any { <-gate.ch; return cleanReport(req) })
	fast := newFakeWebhook(t, "s", cleanReport)
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "fast", fast)
	createHook(t, inst, "slow", slow)
	both := []string{"fast", "slow"}
	inst.CreateRepo("strict", "npm", "hosted", scanSettings(both, "quarantine", map[string]any{"blockUntilScanned": true, "blockOnError": true}))
	inst.CreateRepo("lax", "npm", "hosted", scanSettings(both, "quarantine", map[string]any{"blockUntilScanned": true}))
	startWorkers(t, inst)

	strictURL := publishNPM(t, inst, "strict", "left-pad", "1.3.0", testutil.BootstrapToken)
	laxURL := publishNPM(t, inst, "lax", "left-pad", "1.3.0", testutil.BootstrapToken)
	cs := findComponent(t, inst, "strict", "left-pad", "1.3.0")
	cl := findComponent(t, inst, "lax", "left-pad", "1.3.0")
	waitFor(t, func() bool { return hasResult(t, inst, cs.ID, "fast") && hasResult(t, inst, cl.ID, "fast") })

	// lax: the fast scanner's clean result releases the download.
	waitFor(t, func() bool { return storedState(t, inst, cl.ID) == "clean" })
	testutil.Expect(t, inst.Do("GET", laxURL, testutil.BootstrapToken, nil), http.StatusOK)
	// strict: still pending while the slow scanner runs.
	if st := storedState(t, inst, cs.ID); st != "pending" {
		t.Fatalf("strict state = %s, want pending", st)
	}
	body := testutil.Expect(t, inst.Do("GET", strictURL, testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "has not been scanned yet") {
		t.Fatalf("body: %s", body)
	}

	gate.release()
	waitState(t, inst, cs.ID, "clean")
	testutil.Expect(t, inst.Do("GET", strictURL, testutil.BootstrapToken, nil), http.StatusOK)
}

// blockOnError fails closed: a component whose scan failed is blocked until
// a retry succeeds. Without it, a failed scan is served as before.
func TestBlockOnErrorAndRetries(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any {
		if failing.Load() {
			return map[string]any{"error": "engine unavailable"}
		}
		return cleanReport(req)
	})
	inst := newInst(t, func(c *config.Config) { c.Scan.ErrorRetryInterval = time.Millisecond })
	createHook(t, inst, "av", hook)
	inst.CreateRepo("closed", "npm", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "blockOnError": true}))
	inst.CreateRepo("open", "npm", "hosted", scanSettings([]string{"av"}, "quarantine", map[string]any{"blockUntilScanned": true}))
	startWorkers(t, inst)

	closedURL := publishNPM(t, inst, "closed", "left-pad", "1.3.0", testutil.BootstrapToken)
	openURL := publishNPM(t, inst, "open", "left-pad", "1.3.0", testutil.BootstrapToken)
	cc := findComponent(t, inst, "closed", "left-pad", "1.3.0")
	co := findComponent(t, inst, "open", "left-pad", "1.3.0")
	waitState(t, inst, cc.ID, "error")
	waitState(t, inst, co.ID, "error")

	body := testutil.Expect(t, inst.Do("GET", closedURL, testutil.BootstrapToken, nil), http.StatusForbidden)
	if !strings.Contains(body, "could not be scanned") {
		t.Fatalf("body: %s", body)
	}
	testutil.Expect(t, inst.Do("GET", openURL, testutil.BootstrapToken, nil), http.StatusOK)

	// The scanner recovers; the retry pass only retries the fail-closed repository.
	failing.Store(false)
	n, err := inst.App.Scan.RetryNow(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("retries = %d, %v", n, err)
	}
	s := waitState(t, inst, cc.ID, "clean")
	if s.Jobs[0].Reason != "retry" {
		t.Fatalf("jobs: %+v", s.Jobs)
	}
	testutil.Expect(t, inst.Do("GET", closedURL, testutil.BootstrapToken, nil), http.StatusOK)
	if st := storedState(t, inst, co.ID); st != "error" {
		t.Fatalf("open repository state = %s", st)
	}
}

// A file added to a component while its scan runs makes the result stale:
// the component stays pending and is scanned again. The PyPI .metadata
// sidecar is not new content.
func TestNewFileRescansComponent(t *testing.T) {
	var reqs atomic.Int32
	gate := newReleaser(t)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any {
		if reqs.Add(1) == 1 {
			<-gate.ch
		}
		return cleanReport(req)
	})
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "av", hook)
	inst.CreateRepo("py", "pypi", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "blockOnError": true}))
	startWorkers(t, inst)

	whl1, name1 := testWheel(t, "demo", "1.0", "py3")
	testutil.Expect(t, uploadFile(t, inst, "py", name1, whl1), http.StatusCreated)
	c := findComponent(t, inst, "py", "demo", "1.0")
	if rev := contentRev(t, inst, c.ID); rev != 1 {
		t.Fatalf("content_rev after one wheel = %d", rev)
	}
	waitFor(t, func() bool { return reqs.Load() == 1 })

	// A second wheel arrives while the first scan is still running.
	whl2, name2 := testWheel(t, "demo", "1.0", "py2.py3")
	testutil.Expect(t, uploadFile(t, inst, "py", name2, whl2), http.StatusCreated)
	if rev := contentRev(t, inst, c.ID); rev != 2 {
		t.Fatalf("content_rev after two wheels = %d", rev)
	}
	url1 := "/repository/py/packages/demo/1.0/" + name1
	testutil.Expect(t, inst.Do("GET", url1, testutil.BootstrapToken, nil), http.StatusForbidden)

	gate.release()
	s := waitState(t, inst, c.ID, "clean")
	if reqs.Load() != 2 || len(s.Results) != 1 {
		t.Fatalf("scans = %d, results %+v", reqs.Load(), s.Results)
	}
	testutil.Expect(t, inst.Do("GET", url1, testutil.BootstrapToken, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/py/packages/demo/1.0/"+name2, testutil.BootstrapToken, nil), http.StatusOK)
}

func contentRev(t *testing.T, inst *testutil.Instance, id string) int64 {
	t.Helper()
	var rev int64
	if err := inst.App.Pool.QueryRow(context.Background(), `SELECT content_rev FROM components WHERE id=$1`, id).Scan(&rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

// testWheel builds a minimal wheel for name==version with the python tag.
func testWheel(t *testing.T, name, version, pyTag string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dist := strings.ReplaceAll(name, "-", "_") + "-" + version
	files := map[string]string{
		dist + ".dist-info/METADATA": "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n",
		dist + ".dist-info/WHEEL":    "Wheel-Version: 1.0\nTag: " + pyTag + "-none-any\n",
	}
	for n, c := range files {
		f, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(c))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), dist + "-" + pyTag + "-none-any.whl"
}

// uploadFile uploads through the management API.
func uploadFile(t *testing.T, inst *testutil.Instance, repoName, filename string, content []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write(content)
	_ = mw.Close()
	return inst.Do("POST", "/api/v1/repositories/"+repoName+"/upload", testutil.BootstrapToken, &body, "Content-Type", mw.FormDataContentType())
}
