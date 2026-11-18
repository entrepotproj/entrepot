// Package testutil starts a complete Entrepot instance for integration tests.
//
// Tests using it are skipped unless ENTREPOT_TEST_DATABASE_URL points at a
// Postgres server where the user may create databases, e.g.
//
//	ENTREPOT_TEST_DATABASE_URL=postgres://postgres@localhost:5432/postgres?sslmode=disable
//
// Each call to New creates (and later drops) a fresh database.
package testutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/geoffo-dev/package-repository/internal/app"
	"github.com/geoffo-dev/package-repository/internal/config"
)

const BootstrapToken = "test-bootstrap-token"

type Instance struct {
	T      *testing.T
	App    *app.App
	Server *httptest.Server
	URL    string
	Config *config.Config
}

// Option customises the configuration before the instance starts.
type Option func(*config.Config)

// New starts an instance, or skips the test when no database is configured.
func New(t *testing.T, opts ...Option) *Instance {
	t.Helper()
	admin := os.Getenv("ENTREPOT_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("ENTREPOT_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	dbName := "entrepot_test_" + randHex(6)
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create db: %v", err)
	}
	conn.Close(ctx)
	u, _ := url.Parse(admin)
	u.Path = "/" + dbName

	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Database.URL = u.String()
	cfg.Database.MaxConns = 10
	cfg.Auth.SessionSecret = strings.Repeat("s", 32)
	cfg.Auth.BootstrapToken = BootstrapToken
	cfg.Storage.AllowedRoots = []string{dataDir}
	cfg.Storage.TempDir = t.TempDir()
	cfg.Proxy.Timeout = 30 * time.Second

	// The server URL is only known after starting; use a deferred handler.
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	cfg.Server.BaseURL = srv.URL
	for _, o := range opts {
		o(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	level := slog.LevelWarn
	if os.Getenv("ENTREPOT_TEST_DEBUG") != "" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		srv.Close()
		t.Fatalf("app: %v", err)
	}
	handler = a.Handler()
	inst := &Instance{T: t, App: a, Server: srv, URL: srv.URL, Config: cfg}
	t.Cleanup(func() {
		srv.Close()
		a.Close()
		conn, err := pgx.Connect(context.Background(), admin)
		if err == nil {
			_, _ = conn.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
			conn.Close(context.Background())
		}
	})
	return inst
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Do performs a request with the bootstrap admin token (token "" = anonymous).
func (i *Instance) Do(method, path, token string, body io.Reader, headers ...string) *http.Response {
	i.T.Helper()
	req, err := http.NewRequest(method, i.URL+path, body)
	if err != nil {
		i.T.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k := 0; k+1 < len(headers); k += 2 {
		req.Header.Set(headers[k], headers[k+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		i.T.Fatal(err)
	}
	return resp
}

// JSON performs an admin API call and decodes the response into out (if
// non-nil). It fails the test unless the status equals want.
func (i *Instance) JSON(method, path string, in any, want int, out any) {
	i.T.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	resp := i.Do(method, "/api/v1"+path, BootstrapToken, body, "Content-Type", "application/json")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		i.T.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			i.T.Fatalf("decode %s: %v: %s", path, err, raw)
		}
	}
}

// CreateRepo creates a repository on the default blob store. extra is merged
// into the request (e.g. {"proxy": {"remoteUrl": "..."}}).
func (i *Instance) CreateRepo(name, format, kind string, extra map[string]any) {
	i.T.Helper()
	body := map[string]any{"name": name, "format": format, "kind": kind, "blobStore": "default"}
	for k, v := range extra {
		body[k] = v
	}
	i.JSON(http.MethodPost, "/repositories", body, http.StatusCreated, nil)
}

// Token creates a service account with the given role on pattern and
// returns an API token for it.
func (i *Instance) Token(name, role, pattern string) string {
	i.T.Helper()
	i.JSON(http.MethodPost, "/service-accounts", map[string]any{"name": name}, http.StatusCreated, nil)
	i.JSON(http.MethodPost, "/role-bindings", map[string]any{
		"role": role, "subjectType": "user", "subject": "sa:" + name, "repositoryPattern": pattern,
	}, http.StatusCreated, nil)
	var out struct {
		Secret string `json:"secret"`
	}
	i.JSON(http.MethodPost, "/service-accounts/"+name+"/tokens", map[string]any{"name": "test"}, http.StatusCreated, &out)
	return out.Secret
}

// Body reads and closes a response body.
func Body(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// Expect fails the test when the response status differs from want.
func Expect(t *testing.T, resp *http.Response, want int) string {
	t.Helper()
	b := Body(resp)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", resp.Request.Method, resp.Request.URL, resp.StatusCode, want, b)
	}
	return b
}

