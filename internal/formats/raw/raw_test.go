package raw_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

func TestHostedRaw(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("files", "raw", "hosted", nil)
	writer := inst.Token("ci", "developer", "files")
	reader := inst.Token("viewer", "viewer", "*")

	// Upload requires write.
	testutil.Expect(t, inst.Do("PUT", "/repository/files/dir/a.txt", "", strings.NewReader("x")), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("PUT", "/repository/files/dir/a.txt", reader, strings.NewReader("x")), http.StatusForbidden)
	testutil.Expect(t, inst.Do("PUT", "/repository/files/dir/a.txt", writer, strings.NewReader("hello")), http.StatusCreated)

	if got := testutil.Expect(t, inst.Do("GET", "/repository/files/dir/a.txt", reader, nil), http.StatusOK); got != "hello" {
		t.Fatalf("got %q", got)
	}
	// Redeploy is disabled by default.
	testutil.Expect(t, inst.Do("PUT", "/repository/files/dir/a.txt", writer, strings.NewReader("changed")), http.StatusConflict)
	// Same content is idempotent.
	testutil.Expect(t, inst.Do("PUT", "/repository/files/dir/a.txt", writer, strings.NewReader("hello")), http.StatusCreated)

	// Range requests.
	resp := inst.Do("GET", "/repository/files/dir/a.txt", reader, nil, "Range", "bytes=1-2")
	if got := testutil.Expect(t, resp, http.StatusPartialContent); got != "el" {
		t.Fatalf("range got %q", got)
	}
	// Path traversal is rejected.
	testutil.Expect(t, inst.Do("GET", "/repository/files/dir/%2e%2e/x", reader, nil), http.StatusBadRequest)

	// Listing.
	if l := testutil.Expect(t, inst.Do("GET", "/repository/files/dir/", reader, nil), http.StatusOK); !strings.Contains(l, "a.txt") {
		t.Fatalf("listing missing file: %s", l)
	}
	// Delete requires delete permission (developer lacks it).
	testutil.Expect(t, inst.Do("DELETE", "/repository/files/dir/a.txt", writer, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", "/repository/files/dir/a.txt", testutil.BootstrapToken, nil), http.StatusNoContent)
	testutil.Expect(t, inst.Do("GET", "/repository/files/dir/a.txt", reader, nil), http.StatusNotFound)
}

func TestProxyAndGroupRaw(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/releases/tool.tar.gz" {
			w.Header().Set("ETag", `"v1"`)
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Write([]byte("tarball")) //nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	inst := testutil.New(t)
	inst.CreateRepo("remote", "raw", "proxy", map[string]any{
		"anonymousRead": true,
		"proxy":         map[string]any{"remoteUrl": upstream.URL, "metadataTtlSeconds": 3600},
	})
	inst.CreateRepo("local", "raw", "hosted", nil)
	inst.CreateRepo("all", "raw", "group", map[string]any{
		"anonymousRead": true,
		"group":         map[string]any{"members": []string{"local", "remote"}},
	})

	for i := 0; i < 3; i++ {
		if got := testutil.Expect(t, inst.Do("GET", "/repository/remote/releases/tool.tar.gz", "", nil), http.StatusOK); got != "tarball" {
			t.Fatalf("got %q", got)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 upstream hit (cached), got %d", hits.Load())
	}
	// Negative caching of 404s.
	testutil.Expect(t, inst.Do("GET", "/repository/remote/missing", "", nil), http.StatusNotFound)
	testutil.Expect(t, inst.Do("GET", "/repository/remote/missing", "", nil), http.StatusNotFound)
	if hits.Load() != 2 {
		t.Fatalf("expected negative cache, upstream hits = %d", hits.Load())
	}
	// Uploads to proxies are refused.
	testutil.Expect(t, inst.Do("PUT", "/repository/remote/x", testutil.BootstrapToken, strings.NewReader("x")), http.StatusMethodNotAllowed)

	// Group: hosted member wins, falls through to proxy.
	testutil.Expect(t, inst.Do("PUT", "/repository/local/releases/tool.tar.gz", testutil.BootstrapToken, strings.NewReader("local")), http.StatusCreated)
	if got := testutil.Expect(t, inst.Do("GET", "/repository/all/releases/tool.tar.gz", "", nil), http.StatusOK); got != "local" {
		t.Fatalf("group should prefer first member, got %q", got)
	}
}
