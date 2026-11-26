package scan_test

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/config"
	"github.com/entrepotproj/entrepot/internal/scan"
	"github.com/entrepotproj/entrepot/internal/testutil"
)

type gotResponse struct {
	code   int
	body   string
	header http.Header
}

// getAsync downloads path in the background.
func getAsync(inst *testutil.Instance, path string) chan gotResponse {
	ch := make(chan gotResponse, 1)
	go func() {
		resp := inst.Do("GET", path, testutil.BootstrapToken, nil)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- gotResponse{code: resp.StatusCode, body: string(b), header: resp.Header}
	}()
	return ch
}

func await(t *testing.T, ch chan gotResponse) gotResponse {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("download did not return")
		return gotResponse{}
	}
}

func notYet(t *testing.T, ch chan gotResponse, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("returned before the verdict: %d %s", r.code, r.body)
	case <-time.After(d):
	}
}

func criticalOr(clean bool) any {
	if clean {
		return map[string]any{"findings": []any{}}
	}
	return map[string]any{"findings": []map[string]any{{"vulnId": "CVE-2099-1", "severity": "critical", "package": "evil",
		"installedVersion": "1.0.0"}}}
}

// With holdSeconds a download of content being scanned waits for the
// verdict, then is served or blocked.
func TestHoldUntilVerdict(t *testing.T) {
	gate := newReleaser(t)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any {
		<-gate.ch
		return criticalOr(req.Component.Name != "evil")
	})
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "av", hook)
	inst.CreateRepo("npm-hold", "npm", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "holdSeconds": 30}))
	startWorkers(t, inst)

	good := getAsync(inst, publishNPM(t, inst, "npm-hold", "left-pad", "1.3.0", testutil.BootstrapToken))
	evil := getAsync(inst, publishNPM(t, inst, "npm-hold", "evil", "1.0.0", testutil.BootstrapToken))
	notYet(t, good, 500*time.Millisecond)

	gate.release()
	if r := await(t, good); r.code != http.StatusOK || r.body != "tarball of left-pad@1.3.0" {
		t.Fatalf("good: %d %s", r.code, r.body)
	}
	if r := await(t, evil); r.code != http.StatusForbidden || !strings.Contains(r.body, "CVE-2099-1") ||
		r.header.Get("X-Entrepot-Quarantined") != "true" {
		t.Fatalf("evil: %d %s", r.code, r.body)
	}
}

// When the hold runs out the client is asked to retry (503 + Retry-After).
// Without holdSeconds the original immediate 403 is kept (TestBlockUntilScanned).
func TestHoldTimeout(t *testing.T) {
	gate := newReleaser(t)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any { <-gate.ch; return criticalOr(true) })
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "av", hook)
	inst.CreateRepo("npm-short", "npm", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "holdSeconds": 1}))
	startWorkers(t, inst)

	url := publishNPM(t, inst, "npm-short", "left-pad", "1.3.0", testutil.BootstrapToken)
	start := time.Now()
	r := await(t, getAsync(inst, url))
	if r.code != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "10" ||
		r.header.Get("X-Entrepot-Scan-Pending") != "true" || !strings.HasPrefix(r.body, "scan pending:") {
		t.Fatalf("timeout: %d %v %s", r.code, r.header, r.body)
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
		t.Fatalf("held for %s", d)
	}
	gate.release()
	waitState(t, inst, findComponent(t, inst, "npm-short", "left-pad", "1.3.0").ID, "clean")
	testutil.Expect(t, inst.Do("GET", url, testutil.BootstrapToken, nil), http.StatusOK)
}

// Sidecars (PyPI .metadata) are not held: pip reads them while resolving.
func TestHoldSkipsSidecars(t *testing.T) {
	gate := newReleaser(t)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any { <-gate.ch; return criticalOr(true) })
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "av", hook)
	inst.CreateRepo("py-hold", "pypi", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "holdSeconds": 30}))
	startWorkers(t, inst)

	whl, name := testWheel(t, "demo", "1.0", "py3")
	testutil.Expect(t, uploadFile(t, inst, "py-hold", name, whl), http.StatusCreated)
	base := "/repository/py-hold/packages/demo/1.0/" + name
	meta := testutil.Expect(t, inst.Do("GET", base+".metadata", testutil.BootstrapToken, nil), http.StatusOK)
	if !strings.Contains(meta, "Name: demo") {
		t.Fatalf("metadata: %s", meta)
	}
	wheelDL := getAsync(inst, base)
	notYet(t, wheelDL, 300*time.Millisecond)
	gate.release()
	if r := await(t, wheelDL); r.code != http.StatusOK {
		t.Fatalf("wheel: %d %s", r.code, r.body)
	}
}

// A download held by one replica is released when another replica's
// worker finishes the scan.
func TestHoldAcrossReplicas(t *testing.T) {
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any { return criticalOr(true) })
	web := newInst(t, func(c *config.Config) { c.Scan.Workers = 0 })
	createHook(t, web, "av", hook)
	web.CreateRepo("npm-rep", "npm", "hosted", scanSettings([]string{"av"}, "quarantine",
		map[string]any{"blockUntilScanned": true, "holdSeconds": 30}))
	startWorkers(t, web) // no workers: only the notification listener and timers

	worker := testutil.Reopen(t, web)
	worker.Config.Scan.Workers = 2
	worker.App.Scan.RetryBackoff = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.App.Scan.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	r := await(t, getAsync(web, publishNPM(t, web, "npm-rep", "left-pad", "1.3.0", testutil.BootstrapToken)))
	if r.code != http.StatusOK {
		t.Fatalf("held download: %d %s", r.code, r.body)
	}
}

// The first pull through a proxy is held until the scan of the freshly
// cached tarball completes, then served (it used to get 403).
func TestHoldProxyFirstPull(t *testing.T) {
	tgz := []byte("tarball bytes of left-pad 1.3.0")
	sum1 := sha1.Sum(tgz)
	sum512 := sha512.Sum512(tgz)
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/left-pad":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "left-pad", "dist-tags": map[string]string{"latest": "1.3.0"},
				"versions": map[string]any{"1.3.0": map[string]any{"name": "left-pad", "version": "1.3.0",
					"dist": map[string]any{"tarball": upstream.URL + "/left-pad/-/left-pad-1.3.0.tgz",
						"shasum": hex.EncodeToString(sum1[:]), "integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum512[:])}}}})
		case "/left-pad/-/left-pad-1.3.0.tgz":
			_, _ = w.Write(tgz)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	gate := newReleaser(t)
	hook := newFakeWebhook(t, "s", func(req scan.WebhookRequest) any { <-gate.ch; return criticalOr(true) })
	inst := newInst(t)
	defer gate.release()
	createHook(t, inst, "av", hook)
	settings := scanSettings([]string{"av"}, "quarantine", map[string]any{"blockUntilScanned": true, "holdSeconds": 30})
	settings["proxy"] = map[string]any{"remoteUrl": upstream.URL}
	inst.CreateRepo("npm-px", "npm", "proxy", settings)
	startWorkers(t, inst)

	dl := getAsync(inst, "/repository/npm-px/left-pad/-/left-pad-1.3.0.tgz")
	notYet(t, dl, 500*time.Millisecond)
	gate.release()
	if r := await(t, dl); r.code != http.StatusOK || r.body != string(tgz) {
		t.Fatalf("first pull: %d %s", r.code, r.body)
	}
}
