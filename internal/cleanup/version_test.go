package cleanup

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/entrepotproj/entrepot/internal/store"
)

func TestPrerelease(t *testing.T) {
	cases := []struct {
		format, version string
		want            bool
	}{
		{"npm", "1.2.3", false},
		{"npm", "1.2.3-rc.1", true},
		{"npm", "v2.0.0-beta+build.5", true},
		{"helm", "0.1.0", false},
		{"docker", "latest", false},
		{"docker", "1.0-alpha", true},
		{"pypi", "1.0", false},
		{"pypi", "1.0.post1", false},
		{"pypi", "1.0a1", true},
		{"pypi", "1.0.0rc2", true},
		{"pypi", "2.0.dev3", true},
		{"pypi", "1!2.0b1", true},
		{"apt", "1.2-3", false},
		{"apt", "1.2~rc1-1", true},
		{"yum", "2.0-0.1.beta1.el9", true},
		{"raw", "nightly-snapshot", true},
	}
	for _, c := range cases {
		if got := isPrerelease(c.format, c.version); got != c.want {
			t.Errorf("isPrerelease(%s, %s) = %v, want %v", c.format, c.version, got, c.want)
		}
	}
}

func TestVersionOrder(t *testing.T) {
	order := func(format string, vs []string) string {
		sort.SliceStable(vs, func(i, j int) bool {
			a, _ := parseVersion(format, vs[i])
			b, _ := parseVersion(format, vs[j])
			return compareVersions(a, b) < 0
		})
		return strings.Join(vs, " ")
	}
	if got := order("npm", []string{"1.10.0", "1.2.0", "1.2.0-rc.10", "1.2.0-rc.2", "1.2.0-alpha", "0.9.0"}); got != "0.9.0 1.2.0-alpha 1.2.0-rc.2 1.2.0-rc.10 1.2.0 1.10.0" {
		t.Errorf("semver order: %s", got)
	}
	if got := order("pypi", []string{"1.0.post1", "1.0", "1.0rc1", "1.0b2", "1.0a1", "1.0.dev1", "0.9", "1.1", "1!0.1"}); got != "0.9 1.0.dev1 1.0a1 1.0b2 1.0rc1 1.0 1.0.post1 1.1 1!0.1" {
		t.Errorf("pep440 order: %s", got)
	}
}

func TestPolicyMatch(t *testing.T) {
	now := time.Now()
	comp := func(name, version string, ageDays int, downloadedDaysAgo int) *store.CleanupComponent {
		c := &store.CleanupComponent{Component: &store.Component{ID: name + "@" + version, Name: name, Version: version,
			CreatedAt: now.Add(-time.Duration(ageDays) * 24 * time.Hour)}}
		if downloadedDaysAgo >= 0 {
			d := now.Add(-time.Duration(downloadedDaysAgo) * 24 * time.Hour)
			c.LastDownloadedAt = &d
		}
		return c
	}
	all := []*store.CleanupComponent{
		comp("a", "1.0.0", 100, -1),
		comp("a", "1.10.0", 90, 1),
		comp("a", "1.2.0", 80, -1),
		comp("a", "2.0.0-rc.1", 70, -1),
		comp("b", "0.1.0", 5, -1),
		comp("c", "latest", 50, -1), // not semver: ordered by date
		comp("c", "stable", 60, -1),
	}
	ids := func(cs []*store.CleanupComponent) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ID)
		}
		sort.Strings(out)
		return strings.Join(out, " ")
	}
	i := func(n int) *int { return &n }
	s := func(v string) *string { return &v }
	b := true
	cases := []struct {
		c    Criteria
		want string
	}{
		{Criteria{PublishedOlderThanDays: i(30)}, "a@1.0.0 a@1.10.0 a@1.2.0 a@2.0.0-rc.1 c@latest c@stable"},
		{Criteria{LastDownloadedOlderThanDays: i(30)}, "a@1.0.0 a@1.2.0 a@2.0.0-rc.1 c@latest c@stable"},
		{Criteria{KeepLatest: i(2)}, "a@1.0.0 a@1.2.0"},
		{Criteria{KeepLatest: i(1), NameRegex: s("^c$")}, "c@stable"},
		{Criteria{PrereleaseOnly: &b}, "a@2.0.0-rc.1"},
		{Criteria{VersionRegex: s(`^1\.`), PublishedOlderThanDays: i(85)}, "a@1.0.0 a@1.10.0"},
		{Criteria{KeepLatest: i(0), NameRegex: s("^b$")}, "b@0.1.0"},
	}
	for _, c := range cases {
		p, err := Compile("t", "", c.c)
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(p.match("npm", all, now)); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.c, got, c.want)
		}
	}
}

func TestCompileValidation(t *testing.T) {
	i := func(n int) *int { return &n }
	s := func(v string) *string { return &v }
	for _, c := range []struct {
		format string
		c      Criteria
	}{
		{"", Criteria{}},
		{"", Criteria{NameRegex: s("(")}},
		{"", Criteria{VersionRegex: s("[")}},
		{"", Criteria{PublishedOlderThanDays: i(0)}},
		{"", Criteria{KeepLatest: i(-1)}},
		{"npm", Criteria{UntaggedOlderThanDays: i(3)}},
	} {
		if _, err := Compile("t", c.format, c.c); err == nil {
			t.Errorf("Compile(%s, %+v) succeeded", c.format, c.c)
		}
	}
	if _, err := Compile("t", "docker", Criteria{UntaggedOlderThanDays: i(3)}); err != nil {
		t.Error(err)
	}
}
