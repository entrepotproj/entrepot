package helm

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompareVersions(t *testing.T) {
	vs := []string{"1.0.0", "1.10.0", "1.2.0", "1.2.0-rc.10", "1.2.0-rc.2", "1.2.0-alpha", "v2.0.0", "0.9"}
	sort.Slice(vs, func(i, j int) bool { return compareVersions(vs[i], vs[j]) > 0 })
	if got := strings.Join(vs, " "); got != "v2.0.0 1.10.0 1.2.0 1.2.0-rc.10 1.2.0-rc.2 1.2.0-alpha 1.0.0 0.9" {
		t.Fatalf("order: %s", got)
	}
	for _, v := range []string{"1.0.0", "v1.2", "1.2.3-rc.1+build.5", "0.0.1"} {
		if !validVersion(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	for _, v := range []string{"", "latest", "1.0.0.0", "01.2.3", "1.2.3-"} {
		if validVersion(v) {
			t.Errorf("%s should be invalid", v)
		}
	}
}

func TestParseChartYAML(t *testing.T) {
	m, err := parseChartYAML([]byte("apiVersion: v2\nname: demo\nversion: 1.0.0\nappVersion: 1.10\nkubeVersion: '>=1.20'\ndependencies:\n  - name: redis\n    version: 1.x\n    repository: https://x\n    import-values: [{child: a, parent: b}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.AppVersion != "1.10" || m.KubeVersion != ">=1.20" || len(m.Dependencies) != 1 || m.Dependencies[0].Repository != "https://x" {
		t.Fatalf("meta: %+v", m)
	}
	for _, bad := range []string{"name: x\n", "version: 1.0.0\n", "name: '../x'\nversion: 1.0.0\n", "name: x\nversion: one\n", "apiVersion: v9\nname: x\nversion: 1.0.0\n", ": :"} {
		if _, err := parseChartYAML([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

const blockIndex = `apiVersion: v1
entries:
  alpha:
    - name: alpha
      version: 1.10.0
      appVersion: 2.10
      description: |
        Multi-line
          indented
      urls:
        - https://cdn.example.com/alpha-1.10.0.tgz
      digest: ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789
  # comment
  "true":
  - name: "true"
    version: 0.1.0
    urls: [true-0.1.0.tgz]
  beta:
  - name: beta
    version: 2.0.0
    urls:
    - ../other/beta-2.0.0.tgz
  - name: beta
    version: not-semver
    urls: [x.tgz]
  - name: gamma
    version: 1.0.0
    urls: [x.tgz]
generated: "2024-01-01T00:00:00Z"
`

func checkIndex(t *testing.T, ix *chartIndex) {
	t.Helper()
	if len(ix.entries) != 3 || len(ix.entries["beta"]) != 1 || len(ix.entries["true"]) != 1 {
		t.Fatalf("entries: %+v", ix.entries)
	}
	a := ix.entries["alpha"][0]
	if a.Upstream != "https://cdn.example.com/alpha-1.10.0.tgz" || a.Digest != strings.Repeat("abcdef0123456789", 4) {
		t.Fatalf("alpha: %+v", a)
	}
	if b := ix.entries["beta"][0]; b.Upstream != "https://repo.example.com/other/beta-2.0.0.tgz" {
		t.Fatalf("beta upstream %s", b.Upstream)
	}
	if u := ix.entries["true"][0].Upstream; u != "https://repo.example.com/charts/true-0.1.0.tgz" {
		t.Fatalf("true upstream %s", u)
	}
	out := ix.render()
	var doc struct {
		Entries map[string][]struct {
			Version     string   `yaml:"version"`
			AppVersion  string   `yaml:"appVersion"`
			Description string   `yaml:"description"`
			URLs        []string `yaml:"urls"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("rendered index: %v\n%s", err, out)
	}
	e := doc.Entries["alpha"][0]
	if e.Version != "1.10.0" || e.AppVersion != "2.10" || e.Description != "Multi-line\n  indented\n" || e.URLs[0] != "charts/alpha-1.10.0.tgz" {
		t.Fatalf("rendered alpha: %+v\n%s", e, out)
	}
	if doc.Entries["true"][0].URLs[0] != "charts/true-0.1.0.tgz" {
		t.Fatalf("rendered: %s", out)
	}
	if strings.Contains(string(out), "https://cdn.example.com/alpha-1.10.0.tgz") {
		t.Fatalf("upstream URL leaked: %s", out)
	}
}

func TestParseIndexDocument(t *testing.T) {
	base, _ := url.Parse("https://repo.example.com/charts/")
	if chunks, ok := splitEntries([]byte(blockIndex)); !ok || len(chunks) != 3 {
		t.Fatalf("split: %v %d", ok, len(chunks))
	}
	ix, err := parseIndexDocument([]byte(blockIndex), base, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkIndex(t, ix)

	// The same index as JSON (no block layout) is parsed as a whole.
	var v any
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(blockIndex), &n); err != nil {
		t.Fatal(err)
	}
	v = nodeValue(&n)
	js := strings.ReplaceAll(string(mustJSON(t, v)), "\n", "")
	if _, ok := splitEntries([]byte(js)); ok {
		t.Fatal("JSON should not be split")
	}
	ix, err = parseIndexDocument([]byte(js), base, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkIndex(t, ix)

	empty := newIndex().render()
	if !strings.Contains(string(empty), "entries: {}") {
		t.Fatalf("empty index: %s", empty)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
