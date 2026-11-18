package docker_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/geoffo-dev/package-repository/internal/testutil"
)

// ---- helpers ---------------------------------------------------------------

func host(inst *testutil.Instance) string { return strings.TrimPrefix(inst.URL, "http://") }

func ref(t *testing.T, inst *testutil.Instance, s string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(host(inst)+"/"+s, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func basic(tok string) remote.Option {
	if tok == "" {
		return remote.WithAuth(authn.Anonymous)
	}
	return remote.WithAuth(&authn.Basic{Username: "docker", Password: tok})
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// regCode extracts the first OCI error code from a ggcr error.
func regCode(err error) (int, string) {
	var te *transport.Error
	if errors.As(err, &te) {
		if len(te.Errors) > 0 {
			return te.StatusCode, string(te.Errors[0].Code)
		}
		return te.StatusCode, ""
	}
	return 0, ""
}

func errorCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Errors []struct{ Code string } `json:"errors"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Errors) == 0 {
		t.Fatalf("not an OCI error body: %q", body)
	}
	return e.Errors[0].Code
}

func pullAll(t *testing.T, img v1.Image) {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	if _, err := img.RawConfigFile(); err != nil {
		t.Fatal(err)
	}
}

// ---- hosted ----------------------------------------------------------------

func TestHostedPushPull(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("docker-hosted", "docker", "hosted", nil)
	writer := inst.Token("ci", "developer", "docker-hosted")
	reader := inst.Token("viewer", "viewer", "*")
	admin := testutil.BootstrapToken

	img, err := random.Image(2048, 3)
	if err != nil {
		t.Fatal(err)
	}
	dg, _ := img.Digest()
	tagRef := ref(t, inst, "docker-hosted/team/app:v1")

	// Push with ggcr (token dance via basic auth -> /v2/token).
	if err := remote.Write(tagRef, img, basic(writer)); err != nil {
		t.Fatalf("push: %v", err)
	}
	// Read-only token is denied push.
	img2, _ := random.Image(512, 1)
	err = remote.Write(ref(t, inst, "docker-hosted/team/app:v2"), img2, basic(reader))
	if st, code := regCode(err); st != http.StatusForbidden || code != "DENIED" {
		t.Fatalf("reader push: want 403 DENIED, got %v (%d %s)", err, st, code)
	}
	// Anonymous push gets 401.
	err = remote.Write(ref(t, inst, "docker-hosted/team/app:v2"), img2, basic(""))
	if st, _ := regCode(err); st != http.StatusUnauthorized {
		t.Fatalf("anonymous push: want 401, got %v", err)
	}

	// Pull by tag and digest.
	got, err := remote.Image(tagRef, basic(reader))
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if gd, _ := got.Digest(); gd != dg {
		t.Fatalf("digest %s != %s", gd, dg)
	}
	pullAll(t, got)
	byDigest, err := remote.Image(ref(t, inst, "docker-hosted/team/app@"+dg.String()), basic(reader))
	if err != nil {
		t.Fatalf("pull by digest: %v", err)
	}
	pullAll(t, byDigest)
	desc, err := remote.Head(tagRef, basic(reader))
	if err != nil || desc.Digest != dg {
		t.Fatalf("head: %v %v", desc, err)
	}
	mt, _ := img.MediaType()
	if string(desc.MediaType) != string(mt) {
		t.Fatalf("media type %s, want %s", desc.MediaType, mt)
	}
	// Anonymous pull of a private repo is refused.
	if _, err := remote.Image(tagRef, basic("")); err == nil {
		t.Fatal("anonymous pull should fail")
	} else if st, _ := regCode(err); st != http.StatusUnauthorized {
		t.Fatalf("anonymous pull: %v", err)
	}

	// Multi-arch index.
	idx, err := random.Index(1024, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	idxRef := ref(t, inst, "docker-hosted/team/multi:latest")
	if err := remote.WriteIndex(idxRef, idx, basic(writer)); err != nil {
		t.Fatalf("push index: %v", err)
	}
	gi, err := remote.Index(idxRef, basic(reader))
	if err != nil {
		t.Fatal(err)
	}
	im, _ := gi.IndexManifest()
	if len(im.Manifests) != 3 {
		t.Fatalf("index has %d manifests", len(im.Manifests))
	}
	child, err := gi.Image(im.Manifests[1].Digest)
	if err != nil {
		t.Fatal(err)
	}
	pullAll(t, child)

	// Tags list + pagination.
	for _, tg := range []string{"v3", "v2", "a1"} {
		if err := remote.Tag(ref(t, inst, "docker-hosted/team/app:"+tg).(name.Tag), got, basic(writer)); err != nil {
			t.Fatalf("tag %s: %v", tg, err)
		}
	}
	tags, err := remote.List(tagRef.Context(), basic(reader))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tags, ",") != "a1,v1,v2,v3" {
		t.Fatalf("tags = %v", tags)
	}
	resp := inst.Do("GET", "/v2/docker-hosted/team/app/tags/list?n=2", reader, nil)
	body := testutil.Expect(t, resp, http.StatusOK)
	if !strings.Contains(body, `"tags":["a1","v1"]`) || !strings.Contains(resp.Header.Get("Link"), "last=v1") {
		t.Fatalf("page 1: %s link=%q", body, resp.Header.Get("Link"))
	}
	body = testutil.Expect(t, inst.Do("GET", "/v2/docker-hosted/team/app/tags/list?n=2&last=v1", reader, nil), http.StatusOK)
	if !strings.Contains(body, `"tags":["v2","v3"]`) {
		t.Fatalf("page 2: %s", body)
	}
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/docker-hosted/nope/tags/list", reader, nil), http.StatusNotFound)); code != "NAME_UNKNOWN" {
		t.Fatalf("code %s", code)
	}

	// Catalog.
	repos, err := remote.Catalog(t.Context(), ref(t, inst, "x/y").Context().Registry, basic(reader))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(repos, ",") != "docker-hosted/team/app,docker-hosted/team/multi" {
		t.Fatalf("catalog = %v", repos)
	}

	// Error format for unknown manifests/blobs.
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/docker-hosted/team/app/manifests/missing", reader, nil), http.StatusNotFound)); code != "MANIFEST_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	missing := digestOf([]byte("missing"))
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/docker-hosted/team/app/blobs/"+missing, reader, nil), http.StatusNotFound)); code != "BLOB_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/docker-hosted/team/app/blobs/sha256:xyz", reader, nil), http.StatusBadRequest)); code != "DIGEST_INVALID" {
		t.Fatalf("code %s", code)
	}

	// Delete a tag, then the manifest by digest (removes remaining tags).
	if err := remote.Delete(ref(t, inst, "docker-hosted/team/app:a1"), basic(writer)); err == nil {
		t.Fatal("developer should not be able to delete")
	}
	if err := remote.Delete(ref(t, inst, "docker-hosted/team/app:a1"), basic(admin)); err != nil {
		t.Fatalf("delete tag: %v", err)
	}
	if err := remote.Delete(ref(t, inst, "docker-hosted/team/app@"+dg.String()), basic(admin)); err != nil {
		t.Fatalf("delete manifest: %v", err)
	}
	if _, err := remote.Head(tagRef, basic(reader)); err == nil {
		t.Fatal("tag should be gone after deleting its manifest")
	}
	tags, _ = remote.List(tagRef.Context(), basic(reader))
	if len(tags) != 0 {
		t.Fatalf("tags after delete: %v", tags)
	}
}

func TestAuthAndToken(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("pub", "docker", "hosted", map[string]any{"anonymousRead": true})
	writer := inst.Token("ci", "developer", "pub")

	// GET /v2/ anonymously -> Bearer challenge.
	resp := inst.Do("GET", "/v2/", "", nil)
	testutil.Expect(t, resp, http.StatusUnauthorized)
	want := fmt.Sprintf(`Bearer realm="%s/v2/token",service="entrepot"`, inst.URL)
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge %q, want %q", got, want)
	}
	if resp.Header.Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Fatal("missing API version header")
	}
	// Basic auth and bearer both work on /v2/.
	req, _ := http.NewRequest("GET", inst.URL+"/v2/", nil)
	req.SetBasicAuth("anything", writer)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Expect(t, r2, http.StatusOK)

	// Token endpoint: bad credentials -> 401.
	req, _ = http.NewRequest("GET", inst.URL+"/v2/token?service=entrepot&scope=repository:pub/app:pull,push", nil)
	req.SetBasicAuth("x", "wrong")
	r3, _ := http.DefaultClient.Do(req)
	testutil.Expect(t, r3, http.StatusUnauthorized)

	// Valid credentials -> token usable as Bearer.
	req.SetBasicAuth("x", writer)
	r4, _ := http.DefaultClient.Do(req)
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}
	if err := json.Unmarshal([]byte(testutil.Expect(t, r4, http.StatusOK)), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.Token == "" || tr.Token != tr.AccessToken || tr.ExpiresIn != 300 || tr.IssuedAt == "" {
		t.Fatalf("token response %+v", tr)
	}
	testutil.Expect(t, inst.Do("GET", "/v2/", tr.Token, nil), http.StatusOK)
	// An invalid bearer token yields a Bearer challenge so clients re-auth.
	r5 := inst.Do("GET", "/v2/", "garbage.token.value", nil)
	testutil.Expect(t, r5, http.StatusUnauthorized)
	if !strings.HasPrefix(r5.Header.Get("WWW-Authenticate"), "Bearer ") {
		t.Fatal("expected bearer challenge")
	}
	// OAuth2 password grant.
	r6, _ := http.Post(inst.URL+"/v2/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=password&service=entrepot&username=x&password="+writer+"&scope=repository:pub/app:push"))
	testutil.Expect(t, r6, http.StatusOK)

	// Anonymous token is issued too.
	testutil.Expect(t, inst.Do("GET", "/v2/token?scope=repository:pub/app:pull", "", nil), http.StatusOK)

	// Push with writer, then anonymous pull via ggcr (anonymous token dance).
	img, _ := random.Image(256, 1)
	if err := remote.Write(ref(t, inst, "pub/app:1"), img, basic(writer)); err != nil {
		t.Fatal(err)
	}
	got, err := remote.Image(ref(t, inst, "pub/app:1"), basic(""))
	if err != nil {
		t.Fatalf("anonymous pull from anonymousRead repo: %v", err)
	}
	pullAll(t, got)

	// Unauthorized anonymous request carries the scope in the challenge.
	r7 := inst.Do("PUT", "/v2/pub/app/manifests/2", "", strings.NewReader("{}"))
	testutil.Expect(t, r7, http.StatusUnauthorized)
	if c := r7.Header.Get("WWW-Authenticate"); !strings.Contains(c, `scope="repository:pub/app:pull,push"`) {
		t.Fatalf("challenge %q", c)
	}
	// Unknown repositories: anonymous gets a challenge, authenticated NAME_UNKNOWN.
	testutil.Expect(t, inst.Do("GET", "/v2/nope/app/manifests/1", "", nil), http.StatusUnauthorized)
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/nope/app/manifests/1", writer, nil), http.StatusNotFound)); code != "NAME_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	// Names need a repository and an image.
	testutil.Expect(t, inst.Do("GET", "/v2/pub/manifests/1", writer, nil), http.StatusBadRequest)
}

func uploadStart(t *testing.T, inst *testutil.Instance, tok, nameStr string) string {
	t.Helper()
	resp := inst.Do("POST", "/v2/"+nameStr+"/blobs/uploads/", tok, nil)
	testutil.Expect(t, resp, http.StatusAccepted)
	loc := resp.Header.Get("Location")
	if loc == "" || resp.Header.Get("Docker-Upload-UUID") == "" || resp.Header.Get("Range") != "0-0" {
		t.Fatalf("bad upload headers: %v", resp.Header)
	}
	return loc
}

func TestBlobUploads(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("h", "docker", "hosted", nil)
	inst.CreateRepo("other", "docker", "hosted", nil)
	tok := testutil.BootstrapToken
	limited := inst.Token("only-other", "developer", "other")

	blob := bytes.Repeat([]byte("0123456789"), 1000)
	d := digestOf(blob)

	// Chunked: three PATCHes, then PUT ?digest without body.
	loc := uploadStart(t, inst, tok, "h/img")
	off := 0
	for _, n := range []int{3000, 3000, 4000} {
		resp := inst.Do("PATCH", loc, tok, bytes.NewReader(blob[off:off+n]),
			"Content-Range", fmt.Sprintf("%d-%d", off, off+n-1), "Content-Type", "application/octet-stream")
		testutil.Expect(t, resp, http.StatusAccepted)
		off += n
		if got := resp.Header.Get("Range"); got != fmt.Sprintf("0-%d", off-1) {
			t.Fatalf("range %q after %d bytes", got, off)
		}
	}
	// Status.
	st := inst.Do("GET", loc, tok, nil)
	testutil.Expect(t, st, http.StatusNoContent)
	if st.Header.Get("Range") != "0-9999" {
		t.Fatalf("status range %q", st.Header.Get("Range"))
	}
	// Out-of-order chunk -> 416.
	testutil.Expect(t, inst.Do("PATCH", loc, tok, strings.NewReader("x"), "Content-Range", "5-5"), http.StatusRequestedRangeNotSatisfiable)
	// Wrong digest -> DIGEST_INVALID; correct digest -> 201.
	wrong := digestOf([]byte("nope"))
	if code := errorCode(t, testutil.Expect(t, inst.Do("PUT", loc+"?digest="+wrong, tok, nil), http.StatusBadRequest)); code != "DIGEST_INVALID" {
		t.Fatalf("code %s", code)
	}
	resp := inst.Do("PUT", loc+"?digest="+d, tok, nil)
	testutil.Expect(t, resp, http.StatusCreated)
	if resp.Header.Get("Docker-Content-Digest") != d || resp.Header.Get("Location") != "/v2/h/img/blobs/"+d {
		t.Fatalf("complete headers %v", resp.Header)
	}
	// Session is gone.
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", loc, tok, nil), http.StatusNotFound)); code != "BLOB_UPLOAD_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	head := inst.Do("HEAD", "/v2/h/img/blobs/"+d, tok, nil)
	testutil.Expect(t, head, http.StatusOK)
	if head.Header.Get("Content-Length") != "10000" || head.Header.Get("Docker-Content-Digest") != d {
		t.Fatalf("head headers %v", head.Header)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/v2/h/img/blobs/"+d, tok, nil), http.StatusOK); got != string(blob) {
		t.Fatal("blob content mismatch")
	}

	// Chunk + final chunk in PUT body.
	loc = uploadStart(t, inst, tok, "h/img2")
	testutil.Expect(t, inst.Do("PATCH", loc, tok, bytes.NewReader(blob[:5000])), http.StatusAccepted)
	testutil.Expect(t, inst.Do("PUT", loc+"?digest="+d, tok, bytes.NewReader(blob[5000:])), http.StatusCreated)
	testutil.Expect(t, inst.Do("HEAD", "/v2/h/img2/blobs/"+d, tok, nil), http.StatusOK)

	// Monolithic PUT after POST, and monolithic POST ?digest=.
	b2 := []byte("monolithic blob")
	loc = uploadStart(t, inst, tok, "h/img3")
	testutil.Expect(t, inst.Do("PUT", loc+"?digest="+digestOf(b2), tok, bytes.NewReader(b2)), http.StatusCreated)
	b3 := []byte("single post")
	testutil.Expect(t, inst.Do("POST", "/v2/h/img3/blobs/uploads/?digest="+digestOf(b3), tok, bytes.NewReader(b3)), http.StatusCreated)
	testutil.Expect(t, inst.Do("HEAD", "/v2/h/img3/blobs/"+digestOf(b3), tok, nil), http.StatusOK)
	// Empty blob.
	loc = uploadStart(t, inst, tok, "h/img3")
	testutil.Expect(t, inst.Do("PUT", loc+"?digest="+digestOf(nil), tok, nil), http.StatusCreated)

	// Cancel.
	loc = uploadStart(t, inst, tok, "h/img4")
	testutil.Expect(t, inst.Do("PATCH", loc, tok, strings.NewReader("abc")), http.StatusAccepted)
	testutil.Expect(t, inst.Do("DELETE", loc, tok, nil), http.StatusNoContent)
	testutil.Expect(t, inst.Do("PATCH", loc, tok, strings.NewReader("abc")), http.StatusNotFound)
	// Upload sessions are bound to their image.
	loc = uploadStart(t, inst, tok, "h/img4")
	testutil.Expect(t, inst.Do("PATCH", strings.Replace(loc, "/img4/", "/img5/", 1), tok, strings.NewReader("abc")), http.StatusNotFound)

	// Blobs are per image: img4 does not see img's blob.
	testutil.Expect(t, inst.Do("HEAD", "/v2/h/img4/blobs/"+d, tok, nil), http.StatusNotFound)

	// Cross-repo mount: limited token cannot read h -> falls back to a session.
	resp = inst.Do("POST", "/v2/other/x/blobs/uploads/?mount="+d+"&from=h/img", limited, nil)
	testutil.Expect(t, resp, http.StatusAccepted)
	// Admin can mount.
	resp = inst.Do("POST", "/v2/other/x/blobs/uploads/?mount="+d+"&from=h/img", tok, nil)
	testutil.Expect(t, resp, http.StatusCreated)
	if resp.Header.Get("Location") != "/v2/other/x/blobs/"+d {
		t.Fatalf("mount location %q", resp.Header.Get("Location"))
	}
	if got := testutil.Expect(t, inst.Do("GET", "/v2/other/x/blobs/"+d, limited, nil), http.StatusOK); got != string(blob) {
		t.Fatal("mounted blob mismatch")
	}
	// Mount of an unknown blob falls back too.
	testutil.Expect(t, inst.Do("POST", "/v2/other/x/blobs/uploads/?mount="+digestOf([]byte("zz"))+"&from=h/img", tok, nil), http.StatusAccepted)

	// Blob delete requires delete permission.
	testutil.Expect(t, inst.Do("DELETE", "/v2/other/x/blobs/"+d, limited, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", "/v2/other/x/blobs/"+d, tok, nil), http.StatusAccepted)
	testutil.Expect(t, inst.Do("HEAD", "/v2/other/x/blobs/"+d, tok, nil), http.StatusNotFound)
	// ...without affecting the other repository's copy.
	testutil.Expect(t, inst.Do("HEAD", "/v2/h/img/blobs/"+d, tok, nil), http.StatusOK)
}

func TestManifestValidation(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("h", "docker", "hosted", map[string]any{"hosted": map[string]any{"allowRedeploy": false}}) // immutable tags
	inst.CreateRepo("mutable", "docker", "hosted", map[string]any{"hosted": map[string]any{"allowRedeploy": true}})
	tok := testutil.BootstrapToken

	cfg := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgD := digestOf(cfg)
	manifest := func(cfgDigest string) []byte {
		return []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`, cfgDigest, len(cfg)))
	}
	m := manifest(cfgD)
	ct := "application/vnd.oci.image.manifest.v1+json"

	// Missing config blob.
	body := testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/v1", tok, bytes.NewReader(m), "Content-Type", ct), http.StatusBadRequest)
	if code := errorCode(t, body); code != "MANIFEST_BLOB_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	for _, rp := range []string{"h", "mutable"} {
		testutil.Expect(t, inst.Do("POST", "/v2/"+rp+"/app/blobs/uploads/?digest="+cfgD, tok, bytes.NewReader(cfg)), http.StatusCreated)
	}
	// Invalid JSON, mismatched media type, bad digest reference.
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/v1", tok, strings.NewReader("{"), "Content-Type", ct), http.StatusBadRequest)
	if code := errorCode(t, testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/v1", tok, bytes.NewReader(m),
		"Content-Type", "application/vnd.oci.image.index.v1+json"), http.StatusBadRequest)); code != "MANIFEST_INVALID" {
		t.Fatalf("code %s", code)
	}
	if code := errorCode(t, testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/"+digestOf([]byte("x")), tok, bytes.NewReader(m),
		"Content-Type", ct), http.StatusBadRequest)); code != "DIGEST_INVALID" {
		t.Fatalf("code %s", code)
	}
	// Success by tag.
	resp := inst.Do("PUT", "/v2/h/app/manifests/v1", tok, bytes.NewReader(m), "Content-Type", ct)
	testutil.Expect(t, resp, http.StatusCreated)
	md := digestOf(m)
	if resp.Header.Get("Docker-Content-Digest") != md || resp.Header.Get("Location") != "/v2/h/app/manifests/"+md {
		t.Fatalf("headers %v", resp.Header)
	}
	// GET returns exact bytes and Content-Type.
	g := inst.Do("GET", "/v2/h/app/manifests/v1", tok, nil)
	if got := testutil.Expect(t, g, http.StatusOK); got != string(m) {
		t.Fatalf("manifest bytes differ")
	}
	if g.Header.Get("Content-Type") != ct || g.Header.Get("Docker-Content-Digest") != md {
		t.Fatalf("GET headers %v", g.Header)
	}
	// By digest, without Content-Type (inferred from mediaType).
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/"+md, tok, bytes.NewReader(m)), http.StatusCreated)

	// Index referencing an unknown manifest is refused; a known one accepted.
	idx := func(d string) []byte {
		return []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[`+
			`{"mediaType":%q,"digest":%q,"size":%d,"platform":{"architecture":"amd64","os":"linux"}}]}`, ct, d, len(m)))
	}
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/multi", tok, bytes.NewReader(idx(digestOf([]byte("x")))),
		"Content-Type", "application/vnd.oci.image.index.v1+json"), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/multi", tok, bytes.NewReader(idx(md)),
		"Content-Type", "application/vnd.oci.image.index.v1+json"), http.StatusCreated)

	// Schema1 is rejected.
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/old", tok, strings.NewReader(`{"schemaVersion":1,"fsLayers":[]}`),
		"Content-Type", "application/vnd.docker.distribution.manifest.v1+prettyjws"), http.StatusBadRequest)

	// Tags are immutable when the repository disables redeploys (Docker defaults to mutable tags).
	m2 := []byte(strings.Replace(string(m), `"layers":[]`, `"layers":[],"annotations":{"v":"2"}`, 1))
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/v1", tok, bytes.NewReader(m), "Content-Type", ct), http.StatusCreated) // same content: ok
	testutil.Expect(t, inst.Do("PUT", "/v2/h/app/manifests/v1", tok, bytes.NewReader(m2), "Content-Type", ct), http.StatusConflict)
	testutil.Expect(t, inst.Do("PUT", "/v2/mutable/app/manifests/v1", tok, bytes.NewReader(m), "Content-Type", ct), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", "/v2/mutable/app/manifests/v1", tok, bytes.NewReader(m2), "Content-Type", ct), http.StatusCreated)
	if got := testutil.Expect(t, inst.Do("GET", "/v2/mutable/app/manifests/v1", tok, nil), http.StatusOK); got != string(m2) {
		t.Fatal("tag was not moved")
	}
}

// ---- proxy and group -------------------------------------------------------

// fakeUpstream is an in-memory registry protected by Docker token auth.
type fakeUpstream struct {
	srv       *httptest.Server
	user      string
	pass      string
	tokens    atomic.Int32
	manGets   atomic.Int32
	manHeads  atomic.Int32
	blobGets  atomic.Int32
	corrupt   atomic.Bool
	mu        sync.Mutex
	validToks map[string]bool
}

func newFakeUpstream(t *testing.T, user, pass string) *fakeUpstream {
	f := &fakeUpstream{user: user, pass: pass, validToks: map[string]bool{}}
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	cdn := http.NewServeMux()
	cdnSrv := httptest.NewServer(cdn)
	t.Cleanup(cdnSrv.Close)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if f.user != "" {
				u, p, ok := r.BasicAuth()
				if !ok || u != f.user || p != f.pass {
					http.Error(w, "bad credentials", http.StatusUnauthorized)
					return
				}
			}
			if strings.Contains(r.URL.Query().Get("scope"), "private") {
				// Like GHCR: tokens for unknown/private images are denied.
				http.Error(w, `{"errors":[{"code":"DENIED"}]}`, http.StatusForbidden)
				return
			}
			f.tokens.Add(1)
			tok := fmt.Sprintf("tok-%d", f.tokens.Load())
			f.mu.Lock()
			f.validToks[tok] = true
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q,"expires_in":300}`, tok)
			return
		case strings.HasPrefix(r.URL.Path, "/v2/"):
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			f.mu.Lock()
			ok := f.validToks[tok]
			f.mu.Unlock()
			if !ok {
				img := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/", 2)[0]
				img = strings.SplitN(img, "/blobs/", 2)[0]
				img = strings.SplitN(img, "/tags/", 2)[0]
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:%s:pull"`, f.srv.URL, img))
				http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
				return
			}
			if strings.Contains(r.URL.Path, "/manifests/") {
				if r.Method == http.MethodGet {
					f.manGets.Add(1)
				} else if r.Method == http.MethodHead {
					f.manHeads.Add(1)
				}
			}
			if strings.Contains(r.URL.Path, "/blobs/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/uploads/") {
				f.blobGets.Add(1)
				if r.URL.Query().Get("direct") == "" {
					// Like Docker Hub: redirect blob downloads to a CDN.
					http.Redirect(w, r, strings.Replace(cdnSrv.URL, "127.0.0.1", "localhost", 1)+"/cdn"+r.URL.Path, http.StatusTemporaryRedirect)
					return
				}
			}
		}
		reg.ServeHTTP(w, r)
	}))
	cdn.HandleFunc("/cdn/", func(w http.ResponseWriter, r *http.Request) {
		// Redirect target (another host): must not receive registry credentials.
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "credentials leaked to CDN", http.StatusBadRequest)
			return
		}
		req := httptest.NewRequest("GET", strings.TrimPrefix(r.URL.Path, "/cdn")+"?direct=1", nil)
		rec := httptest.NewRecorder()
		reg.ServeHTTP(rec, req)
		b := rec.Body.Bytes()
		if f.corrupt.Load() && len(b) > 0 {
			b = append([]byte{}, b...)
			b[0] ^= 0xff
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.WriteHeader(rec.Code)
		w.Write(b) //nolint:errcheck
	})
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpstream) push(t *testing.T, repoTag string, img v1.Image) {
	t.Helper()
	r, err := name.ParseReference(strings.TrimPrefix(f.srv.URL, "http://")+"/"+repoTag, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img, remote.WithAuth(&authn.Basic{Username: f.user, Password: f.pass})); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func (f *fakeUpstream) pushIndex(t *testing.T, repoTag string, idx v1.ImageIndex) {
	t.Helper()
	r, _ := name.ParseReference(strings.TrimPrefix(f.srv.URL, "http://")+"/"+repoTag, name.Insecure)
	if err := remote.WriteIndex(r, idx, remote.WithAuth(&authn.Basic{Username: f.user, Password: f.pass})); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func TestProxyAndGroup(t *testing.T) {
	up := newFakeUpstream(t, "puser", "ppass")
	img, _ := random.Image(4096, 2)
	dg, _ := img.Digest()
	up.push(t, "library/alpine:3.20", img)
	idx, _ := random.Index(1024, 1, 2)
	up.pushIndex(t, "org/multi:1", idx)

	inst := testutil.New(t)
	inst.CreateRepo("hub", "docker", "proxy", map[string]any{
		"anonymousRead": true,
		"proxy":         map[string]any{"remoteUrl": up.srv.URL, "username": "puser", "password": "ppass", "metadataTtlSeconds": 1},
	})
	inst.CreateRepo("badcreds", "docker", "proxy", map[string]any{
		"proxy": map[string]any{"remoteUrl": up.srv.URL, "username": "puser", "password": "wrong"},
	})
	inst.CreateRepo("local", "docker", "hosted", nil)
	inst.CreateRepo("all", "docker", "group", map[string]any{
		"anonymousRead": true,
		"group":         map[string]any{"members": []string{"local", "hub"}},
	})
	reader := inst.Token("viewer", "viewer", "*")

	// Pull through the proxy, anonymously (repo allows anonymous read).
	pr := ref(t, inst, "hub/library/alpine:3.20")
	got, err := remote.Image(pr, basic(""))
	if err != nil {
		t.Fatalf("proxy pull: %v", err)
	}
	if gd, _ := got.Digest(); gd != dg {
		t.Fatalf("digest %s != %s", gd, dg)
	}
	pullAll(t, got)
	gets, blobs := up.manGets.Load(), up.blobGets.Load()
	if gets != 1 || blobs != 3 { // 2 layers + config
		t.Fatalf("upstream manifest GETs=%d blob GETs=%d", gets, blobs)
	}
	// Second pull is served from cache (tag still fresh, blobs immutable).
	got, _ = remote.Image(pr, basic(reader))
	pullAll(t, got)
	if up.manGets.Load() != gets || up.blobGets.Load() != blobs {
		t.Fatalf("cache miss: manifest GETs=%d blob GETs=%d", up.manGets.Load(), up.blobGets.Load())
	}
	// By digest is cached too (stored when the tag was fetched).
	if _, err := remote.Image(ref(t, inst, "hub/library/alpine@"+dg.String()), basic(reader)); err != nil {
		t.Fatal(err)
	}
	if up.manGets.Load() != gets {
		t.Fatal("digest manifest should come from cache")
	}
	// After the metadata TTL the tag is revalidated with a HEAD only.
	heads := up.manHeads.Load()
	time.Sleep(1100 * time.Millisecond)
	if _, err := remote.Image(pr, basic(reader)); err != nil {
		t.Fatal(err)
	}
	if up.manGets.Load() != gets || up.manHeads.Load() != heads+1 {
		t.Fatalf("revalidation: GETs=%d HEADs=%d", up.manGets.Load(), up.manHeads.Load())
	}
	// Tokens were cached (one per scope).
	if up.tokens.Load() > 3 {
		t.Fatalf("too many upstream token requests: %d", up.tokens.Load())
	}

	// Multi-arch index through the proxy.
	gi, err := remote.Index(ref(t, inst, "hub/org/multi:1"), basic(reader))
	if err != nil {
		t.Fatalf("proxy index: %v", err)
	}
	im, _ := gi.IndexManifest()
	child, err := gi.Image(im.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	pullAll(t, child)

	// Tags list is forwarded upstream.
	tags, err := remote.List(ref(t, inst, "hub/library/alpine:x").Context(), basic(reader))
	if err != nil || strings.Join(tags, ",") != "3.20" {
		t.Fatalf("proxy tags: %v %v", tags, err)
	}
	// Unknown upstream image -> MANIFEST_UNKNOWN.
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/hub/library/missing/manifests/1", reader, nil), http.StatusNotFound)); code != "MANIFEST_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	// Token denied for the image (GHCR style) -> MANIFEST_UNKNOWN.
	if code := errorCode(t, testutil.Expect(t, inst.Do("GET", "/v2/hub/org/private/manifests/1", reader, nil), http.StatusNotFound)); code != "MANIFEST_UNKNOWN" {
		t.Fatalf("code %s", code)
	}
	// Wrong upstream credentials -> failure, nothing cached.
	testutil.Expect(t, inst.Do("GET", "/v2/badcreds/library/alpine/manifests/3.20", testutil.BootstrapToken, nil), http.StatusBadGateway)

	// Corrupted upstream blob is rejected and not cached.
	img2, _ := random.Image(2048, 1)
	up.push(t, "org/corrupt:1", img2)
	l2, _ := img2.Layers()
	ld, _ := l2[0].Digest()
	up.corrupt.Store(true)
	testutil.Expect(t, inst.Do("GET", "/v2/hub/org/corrupt/blobs/"+ld.String(), reader, nil), http.StatusBadGateway)
	up.corrupt.Store(false)
	if got := testutil.Expect(t, inst.Do("GET", "/v2/hub/org/corrupt/blobs/"+ld.String(), reader, nil), http.StatusOK); digestOf([]byte(got)) != ld.String() {
		t.Fatal("blob content wrong after retry")
	}

	// Pushing to a proxy is unsupported.
	err = remote.Write(ref(t, inst, "hub/library/alpine:new"), img, basic(testutil.BootstrapToken))
	if st, code := regCode(err); st != http.StatusMethodNotAllowed || code != "UNSUPPORTED" {
		t.Fatalf("push to proxy: %v", err)
	}

	// Group: hosted member wins; proxy member fills in.
	localImg, _ := random.Image(1024, 1)
	if err := remote.Write(ref(t, inst, "local/library/alpine:3.20"), localImg, basic(testutil.BootstrapToken)); err != nil {
		t.Fatal(err)
	}
	gimg, err := remote.Image(ref(t, inst, "all/library/alpine:3.20"), basic(""))
	if err != nil {
		t.Fatal(err)
	}
	if gd, _ := gimg.Digest(); gd != mustDigest(localImg) {
		t.Fatal("group should prefer the hosted member")
	}
	pullAll(t, gimg)
	gimg, err = remote.Image(ref(t, inst, "all/org/multi@"+im.Manifests[1].Digest.String()), basic(""))
	if err != nil {
		t.Fatalf("group via proxy: %v", err)
	}
	pullAll(t, gimg)
	tags, err = remote.List(ref(t, inst, "all/org/multi:x").Context(), basic(reader))
	if err != nil || strings.Join(tags, ",") != "1" {
		t.Fatalf("group tags: %v %v", tags, err)
	}
	// Pushing to a group is unsupported.
	err = remote.Write(ref(t, inst, "all/x:1"), localImg, basic(testutil.BootstrapToken))
	if st, code := regCode(err); st != http.StatusMethodNotAllowed || code != "UNSUPPORTED" {
		t.Fatalf("push to group: %v", err)
	}

	// Copy from the proxy into hosted (ggcr mounts nothing across stores here,
	// but cross-repo mount from the proxy cache works on the same blob store).
	l, _ := img.Layers()
	ld0, _ := l[0].Digest()
	resp := inst.Do("POST", "/v2/local/copied/blobs/uploads/?mount="+ld0.String()+"&from=hub/library/alpine", testutil.BootstrapToken, nil)
	testutil.Expect(t, resp, http.StatusCreated)

	// Repository validation: proxy remote URLs must be http(s).
	inst.JSON("POST", "/repositories", map[string]any{"name": "bad", "format": "docker", "kind": "proxy", "blobStore": "default",
		"proxy": map[string]any{"remoteUrl": "ftp://example.com"}}, http.StatusBadRequest, nil)
}

func mustDigest(img v1.Image) v1.Hash {
	d, _ := img.Digest()
	return d
}

func TestClientURL(t *testing.T) {
	inst := testutil.New(t)
	inst.CreateRepo("docker-hosted", "docker", "hosted", nil)
	var out map[string]any
	inst.JSON("GET", "/repositories/docker-hosted", nil, http.StatusOK, &out)
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"`+host(inst)+`/docker-hosted"`) {
		t.Fatalf("client URL missing from %s", b)
	}
}
