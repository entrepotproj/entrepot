package match

import "testing"

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "npm-internal", true},
		{"npm-*", "npm-internal", true},
		{"npm-*", "pypi-internal", false},
		{"platform/*", "platform/api", true},
		{"platform/*", "platform/sub/api", false},
		{"platform/**", "platform/sub/api", true},
		{"main|release/*", "release/1.2", true},
		{"main|release/*", "feature/x", false},
		{"true", "true", true},
		{"v?.*", "v1.2", true},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.p, c.s, got, c.want)
		}
	}
}
