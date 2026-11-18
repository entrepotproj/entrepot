package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func TestUsageMetricsActivityAndAudit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream-bytes")) //nolint:errcheck
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("public", "raw", "hosted", map[string]any{"anonymousRead": true})
	inst.CreateRepo("private", "raw", "hosted", nil)
	inst.CreateRepo("remote", "raw", "proxy", map[string]any{"anonymousRead": true, "proxy": map[string]any{"remoteUrl": upstream.URL}})
	ci := inst.Token("ci", "developer", "*")

	testutil.Expect(t, inst.Do("PUT", "/repository/public/app.tgz", ci, strings.NewReader("0123456789"), "User-Agent", "e2e-agent/1.0"), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", "/repository/private/secret.tgz", ci, strings.NewReader("abc")), http.StatusCreated)
	for i := 0; i < 2; i++ {
		testutil.Expect(t, inst.Do("GET", "/repository/public/app.tgz", "", nil), http.StatusOK)
		testutil.Expect(t, inst.Do("GET", "/repository/remote/file.bin", "", nil), http.StatusOK)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/private/secret.tgz", testutil.BootstrapToken, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/public/missing", "", nil), http.StatusNotFound)
	if err := inst.App.Usage.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	type overview struct {
		Scope  string `json:"scope"`
		Totals struct {
			Requests, Downloads, Uploads, BytesOut, BytesIn, CacheHits, CacheMisses int64
		} `json:"totals"`
		Series          []map[string]any `json:"series"`
		TopRepositories []struct {
			Repository string `json:"repository"`
		} `json:"topRepositories"`
		Inventory []map[string]any `json:"inventory"`
		Storage   *[]map[string]any `json:"storage"`
	}
	var admin overview
	inst.JSON("GET", "/metrics/overview?range=1h", nil, http.StatusOK, &admin)
	if admin.Scope != "all" || admin.Storage == nil || len(*admin.Storage) == 0 {
		t.Fatalf("admin scope/storage: %+v", admin)
	}
	tot := admin.Totals
	if tot.Requests < 8 || tot.Downloads != 5 || tot.Uploads != 2 || tot.BytesIn != 13 || tot.CacheHits != 1 || tot.CacheMisses != 1 {
		t.Fatalf("admin totals: %+v", tot)
	}
	if len(admin.Series) < 60 || len(admin.TopRepositories) != 3 {
		t.Fatalf("series %d, top %d", len(admin.Series), len(admin.TopRepositories))
	}

	// Anonymous callers only see public repositories and no storage.
	var anon overview
	_ = json.Unmarshal([]byte(testutil.Expect(t, inst.Do("GET", "/api/v1/metrics/overview?range=24h", "", nil), http.StatusOK)), &anon)
	if anon.Scope != "readable" || anon.Storage != nil {
		t.Fatalf("anonymous scope: %+v", anon)
	}
	for _, r := range anon.TopRepositories {
		if r.Repository == "private" {
			t.Fatal("anonymous caller sees private repository usage")
		}
	}
	if anon.Totals.Uploads != 1 || anon.Totals.Downloads != 4 {
		t.Fatalf("anonymous totals: %+v", anon.Totals)
	}

	var repoReport struct {
		Totals struct{ Downloads int64 } `json:"totals"`
	}
	inst.JSON("GET", "/repositories/public/metrics?range=7d", nil, http.StatusOK, &repoReport)
	if repoReport.Totals.Downloads != 2 {
		t.Fatalf("repository metrics: %+v", repoReport)
	}

	// Activity log: uploads with actor and user agent; downloads recorded.
	var acts []map[string]any
	inst.JSON("GET", "/activity?kind=upload&repository=public", nil, http.StatusOK, &acts)
	if len(acts) != 1 || acts[0]["actor"] != "sa:ci" || acts[0]["userAgent"] != "e2e-agent/1.0" || acts[0]["bytes"] != float64(10) {
		t.Fatalf("upload activity: %v", acts)
	}
	inst.JSON("GET", "/activity?kind=download", nil, http.StatusOK, &acts)
	if len(acts) != 5 {
		t.Fatalf("download activity: %d events", len(acts))
	}
	testutil.Expect(t, inst.Do("GET", "/api/v1/activity", ci, nil), http.StatusForbidden)
	resp := inst.Do("GET", "/api/v1/activity?format=csv", testutil.BootstrapToken, nil)
	body := testutil.Expect(t, resp, http.StatusOK)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(body, "id,at,repository") {
		t.Fatalf("activity csv: %s", body[:min(len(body), 100)])
	}
	// Deletes are recorded.
	testutil.Expect(t, inst.Do("DELETE", "/repository/public/app.tgz", testutil.BootstrapToken, nil), http.StatusNoContent)
	_ = inst.App.Usage.Flush(context.Background())
	inst.JSON("GET", "/activity?kind=delete", nil, http.StatusOK, &acts)
	if len(acts) != 1 || acts[0]["path"] != "app.tgz" {
		t.Fatalf("delete activity: %v", acts)
	}

	// Audit filters and CSV.
	var audit []map[string]any
	inst.JSON("GET", "/audit-events?action=repository.", nil, http.StatusOK, &audit)
	if len(audit) != 3 {
		t.Fatalf("expected 3 repository.* audit events, got %d", len(audit))
	}
	for _, e := range audit {
		if !strings.HasPrefix(e["action"].(string), "repository.") {
			t.Fatalf("filter leaked %v", e["action"])
		}
	}
	resp = inst.Do("GET", "/api/v1/audit-events?format=csv&actor=bootstrap", testutil.BootstrapToken, nil)
	if b := testutil.Expect(t, resp, http.StatusOK); !strings.Contains(b, "repository.create") {
		t.Fatalf("audit csv: %s", b)
	}
}
