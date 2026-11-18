// Package match implements the glob syntax used by role binding repository
// patterns and GitLab trust policy conditions:
//
//	*   matches any sequence of characters except '/'
//	**  matches any sequence of characters including '/'
//	?   matches a single character except '/'
//	a|b alternatives (top level): matches if any alternative matches
//
// Matching is case-sensitive and anchored at both ends.
package match

import "strings"

// Glob reports whether s matches pattern.
func Glob(pattern, s string) bool {
	for _, alt := range strings.Split(pattern, "|") {
		if glob(alt, s) {
			return true
		}
	}
	return false
}

func glob(p, s string) bool {
	for len(p) > 0 {
		switch {
		case strings.HasPrefix(p, "**"):
			rest := strings.TrimLeft(p, "*")
			if rest == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if glob(rest, s[i:]) {
					return true
				}
			}
			return false
		case p[0] == '*':
			rest := p[1:]
			for i := 0; i <= len(s); i++ {
				if glob(rest, s[i:]) {
					return true
				}
				if i < len(s) && s[i] == '/' {
					return false
				}
			}
			return false
		case p[0] == '?':
			if len(s) == 0 || s[0] == '/' {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}
