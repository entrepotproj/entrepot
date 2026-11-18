package npm

import (
	"strings"
	"testing"
)

func TestSplitPackage(t *testing.T) {
	cases := []struct {
		in, name string
		rest     []string
		ok       bool
	}{
		{"left-pad", "left-pad", nil, true},
		{"@types%2fnode", "@types/node", nil, true},
		{"@types%2Fnode/-/node-1.0.0.tgz", "@types/node", []string{"-", "node-1.0.0.tgz"}, true},
		{"@types/node/-rev/3-abc", "@types/node", []string{"-rev", "3-abc"}, true},
		{"@types", "", nil, false},
		{"..%2fetc", "", nil, false},
		{"pkg/%2e%2e", "", nil, false},
	}
	for _, c := range cases {
		name, rest, ok := splitPackage(c.in)
		if ok != c.ok || name != c.name || strings.Join(rest, "|") != strings.Join(c.rest, "|") {
			t.Errorf("splitPackage(%q) = %q %v %v", c.in, name, rest, ok)
		}
	}
	if escapedName("@types/node") != "@types%2fnode" || escapedName("left-pad") != "left-pad" {
		t.Error("escapedName")
	}
}

func TestCompareSemver(t *testing.T) {
	ordered := []string{"0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.2.0", "1.10.0", "2.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		if compareSemver(ordered[i], ordered[i+1]) >= 0 || compareSemver(ordered[i+1], ordered[i]) <= 0 {
			t.Errorf("%s should sort before %s", ordered[i], ordered[i+1])
		}
	}
}

func TestPackumentRoundTrip(t *testing.T) {
	src := `{"_id":"a","name":"a","custom":{"x":[1,2]},"dist-tags":{"latest":"2.0.0","beta":"3.0.0-beta"},
	"versions":{"1.0.0":{"name":"a","version":"1.0.0","readme":"r","scripts":{"postinstall":"x"},"dist":{"tarball":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","shasum":"s"}},
	"2.0.0":{"name":"a","version":"2.0.0","dist":{"tarball":"https://cdn.example/x/a-2.0.0.tgz"}}},
	"time":{"modified":"2020-01-01T00:00:00.000Z"}}`
	p, err := parsePackument([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	p.fixTags()
	if _, ok := p.DistTags["beta"]; ok {
		t.Error("dangling dist-tag kept")
	}
	if p.highest() != "2.0.0" {
		t.Errorf("highest %s", p.highest())
	}
	p.rewrite("http://h/repository/r/", "a")
	out := string(p.bytes())
	for _, want := range []string{`"custom":{"x":[1,2]}`, `"tarball":"http://h/repository/r/a/-/a-1.0.0.tgz"`, `"tarball":"http://h/repository/r/a/-/a-2.0.0.tgz"`, `"shasum":"s"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	ab := string(marshal(p.abbreviated()))
	if strings.Contains(ab, "readme") || strings.Contains(ab, "custom") || !strings.Contains(ab, `"hasInstallScript":true`) || !strings.Contains(ab, `"modified":"2020-01-01T00:00:00.000Z"`) {
		t.Errorf("abbreviated: %s", ab)
	}
}
