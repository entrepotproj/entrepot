package yum_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/entrepotproj/entrepot/internal/formats/yum"
	"github.com/entrepotproj/entrepot/internal/testutil"
)

type repomd struct {
	Data []struct {
		Type         string `xml:"type,attr"`
		Checksum     string `xml:"checksum"`
		OpenChecksum string `xml:"open-checksum"`
		Location     struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Size     int64 `xml:"size"`
		OpenSize int64 `xml:"open-size"`
	} `xml:"data"`
}

type primary struct {
	Packages int `xml:"packages,attr"`
	Package  []struct {
		Name     string `xml:"name"`
		Arch     string `xml:"arch"`
		Checksum string `xml:"checksum"`
		Version  struct {
			Epoch string `xml:"epoch,attr"`
			Ver   string `xml:"ver,attr"`
			Rel   string `xml:"rel,attr"`
		} `xml:"version"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Description string `xml:"description"`
		Format      struct {
			Requires struct {
				Entry []struct {
					Name string `xml:"name,attr"`
					Pre  string `xml:"pre,attr"`
				} `xml:"entry"`
			} `xml:"requires"`
			Files []string `xml:"file"`
		} `xml:"format"`
	} `xml:"package"`
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fetchRepodata verifies repomd.xml's signature and every referenced
// file's checksums, and returns the decoded primary.xml.
func fetchRepodata(t *testing.T, inst *testutil.Instance, base string, kr openpgp.EntityList) (primary, map[string][]byte) {
	t.Helper()
	md := testutil.Expect(t, inst.Do("GET", base+"repodata/repomd.xml", "", nil), http.StatusOK)
	sig := testutil.Expect(t, inst.Do("GET", base+"repodata/repomd.xml.asc", "", nil), http.StatusOK)
	if kr != nil {
		if _, err := openpgp.CheckArmoredDetachedSignature(kr, strings.NewReader(md), strings.NewReader(sig), nil); err != nil {
			t.Fatalf("repomd.xml.asc does not verify: %v", err)
		}
	}
	var doc repomd
	if err := xml.Unmarshal([]byte(md), &doc); err != nil {
		t.Fatalf("repomd.xml: %v", err)
	}
	open := map[string][]byte{}
	for _, d := range doc.Data {
		gz := []byte(testutil.Expect(t, inst.Do("GET", base+d.Location.Href, "", nil), http.StatusOK))
		if sha(gz) != d.Checksum || int64(len(gz)) != d.Size {
			t.Fatalf("%s: checksum/size mismatch", d.Type)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(zr)
		if sha(raw) != d.OpenChecksum || int64(len(raw)) != d.OpenSize {
			t.Fatalf("%s: open checksum/size mismatch", d.Type)
		}
		open[d.Type] = raw
	}
	var p primary
	if err := xml.Unmarshal(open["primary"], &p); err != nil {
		t.Fatalf("primary.xml: %v\n%s", err, open["primary"])
	}
	for _, typ := range []string{"filelists", "other"} {
		var v any
		if err := xml.Unmarshal(open[typ], &v); err != nil && err != io.EOF {
			t.Fatalf("%s.xml: %v", typ, err)
		}
	}
	return p, open
}

func keyring(t *testing.T, inst *testutil.Instance, repo string) openpgp.EntityList {
	t.Helper()
	body := testutil.Expect(t, inst.Do("GET", "/repository/"+repo+"/public.key", "", nil), http.StatusOK)
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return el
}

func TestHostedYum(t *testing.T) {
	inst := testutil.New(t)
	inst.App.Env.Signing.RSABits = 2048
	inst.CreateRepo("rpms", "yum", "hosted", map[string]any{"anonymousRead": true})
	writer := inst.Token("ci", "developer", "rpms")
	kr := keyring(t, inst, "rpms")

	// Empty repository has valid, signed repodata.
	if p, _ := fetchRepodata(t, inst, "/repository/rpms/", kr); p.Packages != 0 {
		t.Fatalf("empty repo lists %d packages", p.Packages)
	}

	rpm := yum.BuildTestRPM("hello", "", "1.0", "1.el9", "x86_64", []byte("payload-1"))
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", "", bytes.NewReader(rpm)), http.StatusUnauthorized)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", writer, bytes.NewReader(rpm)), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", writer, bytes.NewReader(rpm)), http.StatusCreated)
	changed := yum.BuildTestRPM("hello", "", "1.0", "1.el9", "x86_64", []byte("payload-2"))
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", writer, bytes.NewReader(changed)), http.StatusConflict)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/other/hello.rpm", writer, bytes.NewReader(changed)), http.StatusConflict) // same NEVRA
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/bad.rpm", writer, strings.NewReader("nope")), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/repodata/x.rpm", writer, bytes.NewReader(rpm)), http.StatusBadRequest)

	// Generic upload API with a target directory.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", "noarch")
	fw, _ := mw.CreateFormFile("file", "tools-2.0-1.noarch.rpm")
	_, _ = fw.Write(yum.BuildTestRPM("tools", "1", "2.0", "1", "noarch", []byte("tools")))
	_ = mw.Close()
	testutil.Expect(t, inst.Do("POST", "/api/v1/repositories/rpms/upload", testutil.BootstrapToken, &body,
		"Content-Type", mw.FormDataContentType()), http.StatusCreated)

	p, open := fetchRepodata(t, inst, "/repository/rpms/", kr)
	if p.Packages != 2 || len(p.Package) != 2 {
		t.Fatalf("primary lists %d packages", p.Packages)
	}
	h := p.Package[0]
	if h.Name != "hello" || h.Arch != "x86_64" || h.Version.Epoch != "0" || h.Version.Ver != "1.0" || h.Version.Rel != "1.el9" ||
		h.Location.Href != "el9/hello-1.0-1.el9.x86_64.rpm" || h.Checksum != sha(rpm) || h.Description != "A package <for> tests & such." {
		t.Fatalf("primary entry: %+v", h)
	}
	if len(h.Format.Requires.Entry) != 3 || h.Format.Requires.Entry[0].Name != "/bin/sh" || h.Format.Requires.Entry[0].Pre != "1" {
		t.Fatalf("requires: %+v", h.Format.Requires.Entry)
	}
	// Primary lists only primary files (bin/ and /etc/); filelists all.
	if strings.Join(h.Format.Files, ",") != "/usr/bin/hello,/etc/hello.conf" {
		t.Fatalf("primary files: %v", h.Format.Files)
	}
	if !strings.Contains(string(open["filelists"]), "<file>/usr/share/doc/hello/README</file>") ||
		!strings.Contains(string(open["filelists"]), `<file type="ghost">/etc/hello.conf</file>`) {
		t.Fatalf("filelists:\n%s", open["filelists"])
	}
	if !strings.Contains(string(open["other"]), "- oldest</changelog>") {
		t.Fatalf("other:\n%s", open["other"])
	}
	if t2 := p.Package[1]; t2.Name != "tools" || t2.Version.Epoch != "1" || t2.Location.Href != "noarch/tools-2.0-1.noarch.rpm" {
		t.Fatalf("tools entry: %+v", t2)
	}
	if got := testutil.Expect(t, inst.Do("GET", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", "", nil), http.StatusOK); got != string(rpm) {
		t.Fatal("package content differs")
	}
	// Components.
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/search?repository=rpms", nil, http.StatusOK, &comps)
	if len(comps) != 2 {
		t.Fatalf("components: %+v", comps)
	}

	// .repo file.
	repoFile := testutil.Expect(t, inst.Do("GET", "/repository/rpms/entrepot.repo", "", nil), http.StatusOK)
	for _, want := range []string{"[entrepot-rpms]\n", "baseurl=" + inst.URL + "/repository/rpms/\n", "repo_gpgcheck=1\n",
		"gpgcheck=0\n", "gpgkey=" + inst.URL + "/repository/rpms/public.key\n"} {
		if !strings.Contains(repoFile, want) {
			t.Fatalf(".repo lacks %q:\n%s", want, repoFile)
		}
	}

	// Delete regenerates; stale repodata generations are pruned.
	testutil.Expect(t, inst.Do("DELETE", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", writer, nil), http.StatusForbidden)
	testutil.Expect(t, inst.Do("DELETE", "/repository/rpms/el9/hello-1.0-1.el9.x86_64.rpm", testutil.BootstrapToken, nil), http.StatusNoContent)
	if p, _ := fetchRepodata(t, inst, "/repository/rpms/", kr); p.Packages != 1 || p.Package[0].Name != "tools" {
		t.Fatalf("after delete: %+v", p)
	}
	var assets struct{ Items []struct{ Path string } }
	inst.JSON("GET", "/repositories/rpms/assets?prefix=repodata/", nil, http.StatusOK, &assets)
	if len(assets.Items) > 2+3+3 { // repomd + asc, current and previous generation
		t.Fatalf("stale repodata kept: %+v", assets)
	}

	// Rotation re-signs repomd.xml.
	inst.JSON("POST", "/repositories/rpms/signing-key/rotate", nil, http.StatusOK, nil)
	md := testutil.Body(inst.Do("GET", "/repository/rpms/repodata/repomd.xml", "", nil))
	sig := testutil.Body(inst.Do("GET", "/repository/rpms/repodata/repomd.xml.asc", "", nil))
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring(t, inst, "rpms"), strings.NewReader(md), strings.NewReader(sig), nil); err != nil {
		t.Fatalf("not re-signed with the new key: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(kr, strings.NewReader(md), strings.NewReader(sig), nil); err == nil {
		t.Fatal("still signed with the old key")
	}
}

func TestHostedYumDepth(t *testing.T) {
	inst := testutil.New(t)
	inst.App.Env.Signing.RSABits = 2048
	inst.CreateRepo("rpms", "yum", "hosted", map[string]any{"hosted": map[string]any{"yum": map[string]any{"repodataDepth": 2}}})
	tok := testutil.BootstrapToken
	a := yum.BuildTestRPM("a", "", "1", "1", "x86_64", []byte("a"))
	b := yum.BuildTestRPM("b", "", "1", "1", "aarch64", []byte("b"))
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/a-1-1.x86_64.rpm", tok, bytes.NewReader(a)), http.StatusBadRequest)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/x86_64/Packages/a-1-1.x86_64.rpm", tok, bytes.NewReader(a)), http.StatusCreated)
	testutil.Expect(t, inst.Do("PUT", "/repository/rpms/el9/aarch64/b-1-1.aarch64.rpm", tok, bytes.NewReader(b)), http.StatusCreated)

	kr := openpgp.EntityList(nil)
	{
		body := testutil.Body(inst.Do("GET", "/repository/rpms/public.key", tok, nil))
		kr, _ = openpgp.ReadArmoredKeyRing(strings.NewReader(body))
	}
	check := func(base, name, href string) {
		resp := inst.Do("GET", base+"repodata/repomd.xml", tok, nil)
		md := testutil.Expect(t, resp, http.StatusOK)
		var doc repomd
		_ = xml.Unmarshal([]byte(md), &doc)
		var prim []byte
		for _, d := range doc.Data {
			if d.Type == "primary" {
				gz := testutil.Body(inst.Do("GET", base+d.Location.Href, tok, nil))
				zr, _ := gzip.NewReader(strings.NewReader(gz))
				prim, _ = io.ReadAll(zr)
			}
		}
		var p primary
		_ = xml.Unmarshal(prim, &p)
		if p.Packages != 1 || p.Package[0].Name != name || p.Package[0].Location.Href != href {
			t.Fatalf("%s primary: %s", base, prim)
		}
		sig := testutil.Body(inst.Do("GET", base+"repodata/repomd.xml.asc", tok, nil))
		if _, err := openpgp.CheckArmoredDetachedSignature(kr, strings.NewReader(md), strings.NewReader(sig), nil); err != nil {
			t.Fatal(err)
		}
	}
	check("/repository/rpms/el9/x86_64/", "a", "Packages/a-1-1.x86_64.rpm")
	check("/repository/rpms/el9/aarch64/", "b", "b-1-1.aarch64.rpm")
	testutil.Expect(t, inst.Do("GET", "/repository/rpms/repodata/repomd.xml", tok, nil), http.StatusNotFound)
	repoFile := testutil.Body(inst.Do("GET", "/repository/rpms/el9/x86_64/entrepot.repo", tok, nil))
	if !strings.Contains(repoFile, "baseurl="+inst.URL+"/repository/rpms/el9/x86_64/\n") {
		t.Fatalf(".repo: %s", repoFile)
	}

	// Deleting through the management API regenerates that root.
	var assets struct{ Items []struct{ ID, Path string } }
	inst.JSON("GET", "/repositories/rpms/assets?prefix=el9/aarch64/b", nil, http.StatusOK, &assets)
	if len(assets.Items) != 1 {
		t.Fatalf("assets: %+v", assets)
	}
	inst.JSON("DELETE", "/assets/"+assets.Items[0].ID, nil, http.StatusNoContent, nil)
	md := testutil.Body(inst.Do("GET", "/repository/rpms/el9/aarch64/repodata/repomd.xml", tok, nil))
	var doc repomd
	_ = xml.Unmarshal([]byte(md), &doc)
	for _, d := range doc.Data {
		if d.Type == "primary" {
			gz := testutil.Body(inst.Do("GET", "/repository/rpms/el9/aarch64/"+d.Location.Href, tok, nil))
			zr, _ := gzip.NewReader(strings.NewReader(gz))
			prim, _ := io.ReadAll(zr)
			if !strings.Contains(string(prim), `packages="0"`) {
				t.Fatalf("after API delete: %s", prim)
			}
		}
	}
}

func TestProxyYum(t *testing.T) {
	var md atomic.Value
	md.Store("<repomd>v1</repomd>")
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/os/repodata/repomd.xml":
			_, _ = io.WriteString(w, md.Load().(string))
		case "/os/repodata/repomd.xml.asc":
			_, _ = io.WriteString(w, "sig-for-"+md.Load().(string))
		case "/os/repodata/0123456789abcdef0123456789abcdef-primary.xml.gz":
			_, _ = io.WriteString(w, "primary")
		case "/os/Packages/c/curl-7.76.1-26.el9.x86_64.rpm":
			_, _ = io.WriteString(w, "rpm")
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	inst := testutil.New(t)
	inst.CreateRepo("rocky", "yum", "proxy", map[string]any{"anonymousRead": true,
		"proxy": map[string]any{"remoteUrl": upstream.URL + "/os", "metadataTtlSeconds": 3600}})
	get := func(p string) string {
		return testutil.Expect(t, inst.Do("GET", "/repository/rocky/"+p, "", nil), http.StatusOK)
	}
	get("repodata/repomd.xml")
	if got := get("repodata/repomd.xml.asc"); got != "sig-for-<repomd>v1</repomd>" {
		t.Fatal(got)
	}
	get("repodata/0123456789abcdef0123456789abcdef-primary.xml.gz")
	if got := get("Packages/c/curl-7.76.1-26.el9.x86_64.rpm"); got != "rpm" {
		t.Fatal(got)
	}
	n := hits.Load()
	get("repodata/repomd.xml")
	get("repodata/repomd.xml.asc")
	get("repodata/0123456789abcdef0123456789abcdef-primary.xml.gz")
	get("Packages/c/curl-7.76.1-26.el9.x86_64.rpm")
	if hits.Load() != n {
		t.Fatal("cached content was refetched")
	}
	// A refreshed repomd.xml drags its signature along.
	md.Store("<repomd>v2</repomd>")
	testutil.Expect(t, inst.Do("DELETE", "/repository/rocky/repodata/repomd.xml", testutil.BootstrapToken, nil), http.StatusNoContent)
	get("repodata/repomd.xml")
	if got := get("repodata/repomd.xml.asc"); got != "sig-for-<repomd>v2</repomd>" {
		t.Fatalf("stale signature: %s", got)
	}
	var comps []struct{ Name, Version string }
	inst.JSON("GET", "/search?repository=rocky", nil, http.StatusOK, &comps)
	if len(comps) != 1 || comps[0].Name != "curl" || comps[0].Version != "7.76.1-26.el9" {
		t.Fatalf("components: %+v", comps)
	}
	testutil.Expect(t, inst.Do("GET", "/repository/rocky/missing.rpm", "", nil), http.StatusNotFound)
}
