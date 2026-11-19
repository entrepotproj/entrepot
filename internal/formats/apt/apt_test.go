package apt_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/entrepotproj/entrepot/internal/testutil"
)

// buildDeb assembles a minimal .deb (ar: debian-binary, control.tar.gz,
// data.tar.gz).
func buildDeb(t *testing.T, pkg, version, arch, extra string) []byte {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <t@example.com>\n"+
		"Installed-Size: 1\nSection: utils\nPriority: optional\n%sDescription: test package %s\n a longer\n .\n description\n",
		pkg, version, arch, extra, pkg)
	tgz := func(files map[string]string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		for name, body := range files {
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte(body))
		}
		_ = tw.Close()
		_ = zw.Close()
		return buf.Bytes()
	}
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	member := func(name string, body []byte) {
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(body))
		out.Write(body)
		if len(body)%2 == 1 {
			out.WriteByte('\n')
		}
	}
	member("debian-binary", []byte("2.0\n"))
	member("control.tar.gz", tgz(map[string]string{"./control": control}))
	member("data.tar.gz", tgz(map[string]string{"./usr/share/doc/" + pkg + "/README": "hello " + version}))
	return out.Bytes()
}

func keyring(t *testing.T, inst *testutil.Instance, repo string) openpgp.EntityList {
	t.Helper()
	body := testutil.Expect(t, inst.Do("GET", "/repository/"+repo+"/public.key", "", nil), http.StatusOK)
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(body))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	bin := testutil.Expect(t, inst.Do("GET", "/repository/"+repo+"/public.gpg", "", nil), http.StatusOK)
	if _, err := openpgp.ReadKeyRing(strings.NewReader(bin)); err != nil {
		t.Fatalf("read binary public key: %v", err)
	}
	return el
}

func get(t *testing.T, inst *testutil.Instance, path string) string {
	t.Helper()
	return testutil.Expect(t, inst.Do("GET", path, "", nil), http.StatusOK)
}

// verifyRelease checks InRelease and Release.gpg against the key and
// returns the Release text.
func verifyRelease(t *testing.T, inst *testutil.Instance, repo, dist string, kr openpgp.EntityList) string {
	t.Helper()
	release := get(t, inst, "/repository/"+repo+"/dists/"+dist+"/Release")
	sig := get(t, inst, "/repository/"+repo+"/dists/"+dist+"/Release.gpg")
	if _, err := openpgp.CheckDetachedSignature(kr, strings.NewReader(release), strings.NewReader(sig), nil); err != nil {
		t.Fatalf("Release.gpg does not verify: %v", err)
	}
	in := get(t, inst, "/repository/"+repo+"/dists/"+dist+"/InRelease")
	b, _ := clearsign.Decode([]byte(in))
	if b == nil {
		t.Fatalf("InRelease is not clearsigned: %s", in)
	}
	if _, err := b.VerifySignature(kr, nil); err != nil {
		t.Fatalf("InRelease does not verify: %v", err)
	}
	if strings.TrimRight(string(b.Plaintext), "\n") != strings.TrimRight(release, "\n") {
		t.Fatalf("InRelease content differs from Release:\n%s\n---\n%s", b.Plaintext, release)
	}
	return release
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestHostedApt(t *testing.T) {
	inst := testutil.New(t)
	inst.App.Env.Signing.RSABits = 2048
	inst.CreateRepo("debs", "apt", "hosted", map[string]any{"anonymousRead": true})
	writer := inst.Token("ci", "developer", "debs")

	// Empty repository: indexes for the default distribution exist.
	kr := keyring(t, inst, "debs")
	release := verifyRelease(t, inst, "debs", "stable", kr)
	if !strings.Contains(release, "Components: main") || !strings.Contains(release, "Architectures: amd64 arm64") {
		t.Fatalf("unexpected empty Release:\n%s", release)
	}

	deb := buildDeb(t, "hello", "1.0-1", "amd64", "Depends: libc6 (>= 2.34)\n")
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/hello_1.0-1_amd64.deb", "", bytes.NewReader(deb)), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/hello_1.0-1_amd64.deb?distribution=stable&component=main", writer,
		bytes.NewReader(deb)), http.StatusCreated)
	// Same content again is fine; different content is a conflict.
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/x.deb", writer, bytes.NewReader(deb)), http.StatusCreated)
	other := buildDeb(t, "hello", "1.0-1", "amd64", "Recommends: foo\n")
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/x.deb", writer, bytes.NewReader(other)), http.StatusConflict)
	// Not a package.
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/bad.deb", writer, strings.NewReader("nope")), http.StatusBadRequest)

	// Multipart POST, arch all, into another distribution.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("distribution", "testing")
	fw, _ := mw.CreateFormFile("file", "libtool-data_2.0_all.deb")
	_, _ = fw.Write(buildDeb(t, "libtool-data", "1:2.0", "all", ""))
	_ = mw.Close()
	testutil.Expect(t, inst.Do("POST", "/repository/debs/", writer, &body, "Content-Type", mw.FormDataContentType()), http.StatusCreated)

	release = verifyRelease(t, inst, "debs", "stable", kr)
	if !strings.Contains(release, "Architectures: amd64\n") {
		t.Fatalf("architectures not derived from uploads:\n%s", release)
	}
	pk := get(t, inst, "/repository/debs/dists/stable/main/binary-amd64/Packages")
	for _, want := range []string{"Package: hello\n", "Version: 1.0-1\n", "Depends: libc6 (>= 2.34)\n",
		"Filename: pool/main/h/hello/hello_1.0-1_amd64.deb\n", "SHA256: " + sha(string(deb)) + "\n",
		fmt.Sprintf("Size: %d\n", len(deb)), "Description: test package hello\n a longer\n .\n description\n"} {
		if !strings.Contains(pk, want) {
			t.Fatalf("Packages lacks %q:\n%s", want, pk)
		}
	}
	if !strings.Contains(release, sha(pk)) {
		t.Fatalf("Release does not list the Packages hash:\n%s", release)
	}
	gz := get(t, inst, "/repository/debs/dists/stable/main/binary-amd64/Packages.gz")
	zr, err := gzip.NewReader(strings.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	unz, _ := io.ReadAll(zr)
	if string(unz) != pk {
		t.Fatal("Packages.gz differs from Packages")
	}
	if got := get(t, inst, "/repository/debs/pool/main/h/hello/hello_1.0-1_amd64.deb"); got != string(deb) {
		t.Fatal("package content differs")
	}

	// testing has the arch:all package in every architecture.
	verifyRelease(t, inst, "debs", "testing", kr)
	for _, arch := range []string{"amd64", "arm64"} {
		pk := get(t, inst, "/repository/debs/dists/testing/main/binary-"+arch+"/Packages")
		if !strings.Contains(pk, "Package: libtool-data\n") || !strings.Contains(pk, "Filename: pool/main/libt/libtool-data/libtool-data_2.0_all.deb") {
			t.Fatalf("testing %s Packages:\n%s", arch, pk)
		}
	}

	// Upload the same package into testing too: it is listed in both.
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/hello.deb?distribution=testing", writer, bytes.NewReader(deb)), http.StatusCreated)
	if pk := get(t, inst, "/repository/debs/dists/testing/main/binary-amd64/Packages"); !strings.Contains(pk, "Package: hello\n") {
		t.Fatalf("hello missing from testing:\n%s", pk)
	}

	// Delete regenerates (developer cannot delete).
	testutil.Expect(t, inst.Do("DELETE", "/repository/debs/pool/main/h/hello/hello_1.0-1_amd64.deb", writer, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", "/repository/debs/pool/main/h/hello/hello_1.0-1_amd64.deb", testutil.BootstrapToken, nil), http.StatusNoContent)
	if pk := get(t, inst, "/repository/debs/dists/stable/main/binary-amd64/Packages"); strings.Contains(pk, "hello") {
		t.Fatalf("deleted package still listed:\n%s", pk)
	}
	verifyRelease(t, inst, "debs", "stable", kr)

	// Signing key API: rotation re-signs the metadata.
	var key struct {
		Fingerprint, Algorithm, PublicKey, URL string
	}
	inst.JSON("GET", "/repositories/debs/signing-key", nil, http.StatusOK, &key)
	if key.Algorithm != "rsa2048" || !strings.HasSuffix(key.URL, "/repository/debs/public.key") {
		t.Fatalf("signing key: %+v", key)
	}
	var rotated struct{ Fingerprint string }
	inst.JSON("POST", "/repositories/debs/signing-key/rotate", nil, http.StatusOK, &rotated)
	if rotated.Fingerprint == key.Fingerprint {
		t.Fatal("rotation kept the fingerprint")
	}
	kr2 := keyring(t, inst, "debs")
	verifyRelease(t, inst, "debs", "testing", kr2)
	release = get(t, inst, "/repository/debs/dists/testing/Release")
	sig := get(t, inst, "/repository/debs/dists/testing/Release.gpg")
	if _, err := openpgp.CheckDetachedSignature(kr, strings.NewReader(release), strings.NewReader(sig), nil); err == nil {
		t.Fatal("metadata still verifies with the old key")
	}
	// Non-admins cannot rotate.
	resp := inst.Do("POST", "/api/v1/repositories/debs/signing-key/rotate", writer, nil)
	testutil.Expect(t, resp, http.StatusForbidden)

	// Import an existing (passphrase protected) key.
	e, err := openpgp.NewEntity("Acme", "", "apt@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.EncryptPrivateKeys([]byte("pw"), nil)
	var priv bytes.Buffer
	aw, _ := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	_ = e.SerializePrivateWithoutSigning(aw, nil)
	_ = aw.Close()
	inst.JSON("PUT", "/repositories/debs/signing-key", map[string]any{"privateKey": priv.String()}, http.StatusBadRequest, nil)
	var imported struct{ Fingerprint, Algorithm string }
	inst.JSON("PUT", "/repositories/debs/signing-key", map[string]any{"privateKey": priv.String(), "passphrase": "pw"}, http.StatusOK, &imported)
	if imported.Algorithm != "ed25519" || imported.Fingerprint != strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)) {
		t.Fatalf("imported: %+v", imported)
	}
	verifyRelease(t, inst, "debs", "testing", openpgp.EntityList{e})

	// The generic upload API takes distribution/component fields.
	body.Reset()
	mw = multipart.NewWriter(&body)
	_ = mw.WriteField("distribution", "stable")
	_ = mw.WriteField("component", "extra")
	fw, _ = mw.CreateFormFile("file", "zed.deb")
	_, _ = fw.Write(buildDeb(t, "zed", "0.1", "arm64", ""))
	_ = mw.Close()
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/debs/upload", testutil.BootstrapToken, &body,
		"Content-Type", mw.FormDataContentType()), http.StatusCreated)
	release = verifyRelease(t, inst, "debs", "stable", openpgp.EntityList{e})
	if !strings.Contains(release, "Components: extra main\n") || !strings.Contains(release, "extra/binary-arm64/Packages") {
		t.Fatalf("Release after API upload:\n%s", release)
	}
	if pk := get(t, inst, "/repository/debs/dists/stable/extra/binary-arm64/Packages"); !strings.Contains(pk, "Filename: pool/extra/z/zed/zed_0.1_arm64.deb") {
		t.Fatalf("Packages:\n%s", pk)
	}
}

func TestHostedAptConfiguredDistributions(t *testing.T) {
	inst := testutil.New(t)
	inst.App.Env.Signing.RSABits = 2048
	inst.CreateRepo("debs", "apt", "hosted", map[string]any{"hosted": map[string]any{"apt": map[string]any{
		"distributions": []map[string]any{
			{"name": "jammy", "components": []string{"main", "contrib"}, "architectures": []string{"amd64", "all"}, "origin": "Acme", "label": "Acme tools"},
			{"name": "noble"},
		},
	}}})
	tok := testutil.BootstrapToken
	deb := buildDeb(t, "tool", "2.0", "amd64", "")
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/tool.deb", tok, bytes.NewReader(deb)), http.StatusBadRequest) // ambiguous dist
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/tool.deb?distribution=focal", tok, bytes.NewReader(deb)), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/tool.deb?distribution=jammy&component=universe", tok, bytes.NewReader(deb)), http.StatusBadRequest)
	arm := buildDeb(t, "tool", "2.0", "arm64", "")
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/tool.deb?distribution=jammy", tok, bytes.NewReader(arm)), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("PUT", "/repository/debs/tool.deb?distribution=jammy&component=contrib", tok, bytes.NewReader(deb)), http.StatusCreated)

	rel := testutil.Body(inst.Do("GET", "/repository/debs/dists/jammy/Release", tok, nil))
	for _, want := range []string{"Origin: Acme\n", "Label: Acme tools\n", "Architectures: amd64 all\n", "Components: main contrib\n",
		"contrib/binary-amd64/Packages", "contrib/binary-all/Packages", "main/binary-amd64/Packages.gz"} {
		if !strings.Contains(rel, want) {
			t.Fatalf("Release lacks %q:\n%s", want, rel)
		}
	}
	if pk := testutil.Body(inst.Do("GET", "/repository/debs/dists/jammy/contrib/binary-amd64/Packages", tok, nil)); !strings.Contains(pk, "pool/contrib/t/tool/tool_2.0_amd64.deb") {
		t.Fatalf("Packages:\n%s", pk)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/debs/dists/noble/InRelease", tok, nil), http.StatusOK)
	testutil.Expect(t, inst.Do("GET", "/repository/debs/dists/stable/InRelease", tok, nil), http.StatusNotFound)

	// Invalid distribution names are rejected.
	resp := inst.Do("POST", "/api/v1/repositories", tok, strings.NewReader(`{"name":"bad","format":"apt","kind":"hosted","blobStore":"default",
		"hosted":{"apt":{"distributions":[{"name":"a/b"}]}}}`), "Content-Type", "application/json")
	testutil.Expect(t, resp, http.StatusBadRequest)
}

func TestProxyApt(t *testing.T) {
	packages := "Package: hello\nVersion: 2.10\nArchitecture: amd64\nFilename: pool/main/h/hello/hello_2.10_amd64.deb\n\n"
	packages2 := packages + "Package: world\nVersion: 1\nArchitecture: amd64\nFilename: pool/main/w/world/world_1_amd64.deb\n\n"
	var current atomic.Value
	current.Store(packages)
	release := func() string {
		p := current.Load().(string)
		return fmt.Sprintf("Suite: noble\nSHA256:\n %s %d main/binary-amd64/Packages\n", sha(p), len(p))
	}
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ubuntu/dists/noble/InRelease":
			_, _ = io.WriteString(w, release())
		case "/ubuntu/dists/noble/main/binary-amd64/Packages":
			_, _ = io.WriteString(w, current.Load().(string))
		case "/ubuntu/pool/main/h/hello/hello_2.10_amd64.deb":
			_, _ = io.WriteString(w, "debcontent")
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	inst := testutil.New(t)
	inst.CreateRepo("ubuntu", "apt", "proxy", map[string]any{"anonymousRead": true,
		"proxy": map[string]any{"remoteUrl": upstream.URL + "/ubuntu", "metadataTtlSeconds": 3600}})

	get(t, inst, "/repository/ubuntu/dists/noble/InRelease")
	if got := get(t, inst, "/repository/ubuntu/dists/noble/main/binary-amd64/Packages"); got != packages {
		t.Fatalf("Packages: %q", got)
	}
	if got := get(t, inst, "/repository/ubuntu/pool/main/h/hello/hello_2.10_amd64.deb"); got != "debcontent" {
		t.Fatalf("deb: %q", got)
	}
	n := hits.Load()
	get(t, inst, "/repository/ubuntu/pool/main/h/hello/hello_2.10_amd64.deb")
	get(t, inst, "/repository/ubuntu/dists/noble/main/binary-amd64/Packages")
	if hits.Load() != n {
		t.Fatal("cached content was refetched")
	}
	// Upstream publishes a new Release; once the cached InRelease is
	// refreshed the stale Packages no longer matches and is refetched.
	current.Store(packages2)
	testutil.Expect(t, inst.Do("DELETE", "/repository/ubuntu/dists/noble/InRelease", testutil.BootstrapToken, nil), http.StatusNoContent)
	get(t, inst, "/repository/ubuntu/dists/noble/InRelease")
	if got := get(t, inst, "/repository/ubuntu/dists/noble/main/binary-amd64/Packages"); got != packages2 {
		t.Fatalf("stale Packages served after Release changed: %q", got)
	}
	// Components are recorded for pool files.
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/search?repository=ubuntu", nil, http.StatusOK, &comps)
	if len(comps) != 1 || comps[0].Name != "hello" || comps[0].Version != "2.10" {
		t.Fatalf("components: %+v", comps)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/ubuntu/dists/noble/main/binary-i386/Packages", "", nil), http.StatusNotFound)
	// Uploads are refused.
	testutil.Expect(t, inst.Do("PUT", "/repository/ubuntu/x.deb", testutil.BootstrapToken, strings.NewReader("x")), http.StatusMethodNotAllowed)
	// Signing keys only exist for hosted repositories.
	resp := inst.Do("GET", "/api/v1/repositories/ubuntu/signing-key", testutil.BootstrapToken, nil)
	testutil.Expect(t, resp, http.StatusBadRequest)
}
