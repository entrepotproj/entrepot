package pypi

import (
	"net/http/httptest"
	"testing"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"Django": "django", "zope.interface": "zope-interface", "My__Pkg-._x": "my-pkg-x"} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	if ValidName("-bad") || ValidName("a/b") || !ValidName("a.b_c-d") {
		t.Error("ValidName")
	}
}

func TestParseFilename(t *testing.T) {
	cases := []struct{ file, project, name, version, kind string }{
		{"requests-2.31.0-py3-none-any.whl", "", "requests", "2.31.0", kindWheel},
		{"numpy-1.26.0-1-cp312-cp312-manylinux_2_17_x86_64.whl", "", "numpy", "1.26.0", kindWheel},
		{"python-dateutil-2.8.2.tar.gz", "", "python-dateutil", "2.8.2", kindSdist},
		{"pkg-3d-1.0.tar.gz", "pkg-3d", "pkg-3d", "1.0", kindSdist},
		{"foo-1.0.zip", "", "foo", "1.0", kindSdist},
		{"foo-1.0-py2.7.egg", "", "foo", "1.0", kindEgg},
	}
	for _, c := range cases {
		n, v, k, ok := parseFilename(c.file, c.project)
		if !ok || n != c.name || v != c.version || k != c.kind {
			t.Errorf("parseFilename(%q) = %q %q %q %v", c.file, n, v, k, ok)
		}
	}
	if _, _, _, ok := parseFilename("README.txt", ""); ok {
		t.Error("README.txt accepted")
	}
}

func TestNegotiate(t *testing.T) {
	cases := map[string]string{
		"": "text/html",
		"application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01": jsonType,
		"text/html":                           "text/html",
		"application/vnd.pypi.simple.v1+html": htmlType,
		"*/*":                                 "text/html",
		"application/vnd.pypi.simple.v1+json;q=0, text/html": "text/html",
	}
	for accept, want := range cases {
		r := httptest.NewRequest("GET", "/simple/", nil)
		r.Header.Set("Accept", accept)
		if got := negotiate(r); got != want {
			t.Errorf("negotiate(%q) = %q, want %q", accept, got, want)
		}
	}
}

func TestParseHTMLIndex(t *testing.T) {
	body := []byte(`<html><body>
<a href="https://files.example/p/a/demo-1.0.tar.gz#sha256=abc" data-requires-python="&gt;=3.7">demo-1.0.tar.gz</a>
<a data-core-metadata="sha256=def" href='../../p/demo-1.1-py3-none-any.whl#sha256=123' data-yanked="">demo-1.1-py3-none-any.whl</a>
</body></html>`)
	pg, err := parseIndex(body, "text/html", "https://up.example/simple/demo/", "demo")
	if err != nil || len(pg.Files) != 2 {
		t.Fatalf("%v %+v", err, pg)
	}
	f0, f1 := pg.Files[0], pg.Files[1]
	if f0.URL != "https://files.example/p/a/demo-1.0.tar.gz" || f0.Hashes["sha256"] != "abc" || f0.RequiresPython != ">=3.7" || f0.Path != "packages/demo/1.0/demo-1.0.tar.gz" {
		t.Errorf("file 0: %+v", f0)
	}
	if f1.URL != "https://up.example/p/demo-1.1-py3-none-any.whl" || !f1.HasMetadata || f1.MetadataHashes["sha256"] != "def" || !f1.Yanked {
		t.Errorf("file 1: %+v", f1)
	}
	if len(pg.Versions) != 2 {
		t.Errorf("versions %v", pg.Versions)
	}
}

func TestParseMetadata(t *testing.T) {
	m := parseMetadata([]byte("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nSummary: A\n  continued\nRequires-Python: >=3.8\n\nBody text\n"))
	if m.Name != "demo" || m.Version != "1.0" || m.Summary != "A\ncontinued" || m.RequiresPython != ">=3.8" || m.Description != "Body text" {
		t.Errorf("%+v", m)
	}
}
