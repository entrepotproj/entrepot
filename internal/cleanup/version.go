package cleanup

import (
	"regexp"
	"strconv"
	"strings"
)

// Version handling for keepLatest and prereleaseOnly. Formats use
// different version schemes; this is a best-effort, format-aware view:
//
//	pypi       PEP 440 (1.0.0, 1!2.0, 1.0a1, 1.0rc2, 1.0.post1, 1.0.dev3)
//	apt, yum   not parsed (ordered by publish date); pre-release when the
//	           version contains "~" or an alpha/beta/rc/dev/pre/snapshot marker
//	others     SemVer, leniently (v1.2, 1.2.3-rc.1+build)

type version struct {
	// nums are the release numbers (epoch first for PEP 440).
	nums []int
	// pre is the pre-release part (semver identifiers, or PEP 440 a/b/rc
	// encoded as phase + number).
	pre []string
	// PEP 440 extras.
	pepPre     int // 0 none, 1 a, 2 b, 3 rc
	pepPreN    int
	post, dev  int // -1 when absent
	prerelease bool
	pep        bool
}

var (
	semverRe = regexp.MustCompile(`^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)
	pep440Re = regexp.MustCompile(`(?i)^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
		`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
		`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?` +
		`(?:[-_.]?(dev)[-_.]?(\d*))?` +
		`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)
	debPreRe = regexp.MustCompile(`(?i)(~|alpha|beta|rc\d*|dev|pre|snapshot)`)
)

// parseVersion parses v for the given format; ok is false when the version
// is not in the format's scheme (or the format is not ordered by version).
func parseVersion(format, v string) (version, bool) {
	switch format {
	case "pypi":
		return parsePEP440(v)
	case "apt", "yum":
		return version{prerelease: debPreRe.MatchString(v)}, false
	default:
		return parseSemver(v)
	}
}

// isPrerelease reports whether v is a pre-release in the format's scheme.
func isPrerelease(format, v string) bool {
	pv, ok := parseVersion(format, v)
	if ok || format == "apt" || format == "yum" {
		return pv.prerelease
	}
	// Unparseable: look for common markers.
	return debPreRe.MatchString(v)
}

func parseSemver(v string) (version, bool) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return version{}, false
	}
	out := version{nums: make([]int, 3), post: -1, dev: -1}
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return version{}, false
			}
			out.nums[i] = n
		}
	}
	if m[4] != "" {
		out.pre = strings.Split(m[4], ".")
		out.prerelease = true
	}
	return out, true
}

func parsePEP440(v string) (version, bool) {
	m := pep440Re.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return version{}, false
	}
	out := version{pep: true, post: -1, dev: -1}
	epoch := 0
	if m[1] != "" {
		epoch, _ = strconv.Atoi(m[1])
	}
	out.nums = append(out.nums, epoch)
	for _, p := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return version{}, false
		}
		out.nums = append(out.nums, n)
	}
	// Trailing zeros are insignificant (1.0 == 1.0.0).
	for len(out.nums) > 2 && out.nums[len(out.nums)-1] == 0 {
		out.nums = out.nums[:len(out.nums)-1]
	}
	if m[3] != "" {
		switch strings.ToLower(m[3]) {
		case "a", "alpha":
			out.pepPre = 1
		case "b", "beta":
			out.pepPre = 2
		default:
			out.pepPre = 3
		}
		out.pepPreN, _ = strconv.Atoi(m[4])
		out.prerelease = true
	}
	switch {
	case m[5] != "":
		out.post, _ = strconv.Atoi(m[5])
	case m[6] != "":
		out.post, _ = strconv.Atoi(m[7])
	}
	if m[8] != "" {
		out.dev, _ = strconv.Atoi(m[9])
		out.prerelease = true
	}
	return out, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareVersions orders two parsed versions of the same scheme.
func compareVersions(a, b version) int {
	for i := 0; i < len(a.nums) || i < len(b.nums); i++ {
		var x, y int
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	if a.pep || b.pep {
		return comparePEP(a, b)
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		na, ea := strconv.Atoi(a.pre[i])
		nb, eb := strconv.Atoi(b.pre[i])
		switch {
		case ea == nil && eb == nil:
			if c := cmpInt(na, nb); c != 0 {
				return c
			}
		case ea == nil:
			return -1
		case eb == nil:
			return 1
		default:
			if c := strings.Compare(a.pre[i], b.pre[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a.pre), len(b.pre))
}

// pepKey orders the suffixes of PEP 440 versions with equal releases:
// X.devN < XaN < XbN < XrcN < X < X.postN (dev releases of pre/post
// releases sort just before them).
func comparePEP(a, b version) int {
	ka, kb := pepPhase(a), pepPhase(b)
	if c := cmpInt(ka, kb); c != 0 {
		return c
	}
	if c := cmpInt(a.pepPreN, b.pepPreN); c != 0 {
		return c
	}
	if c := cmpInt(a.post, b.post); c != 0 {
		return c
	}
	// A dev release sorts before the corresponding non-dev release.
	da, db := a.dev, b.dev
	if da < 0 {
		da = 1 << 30
	}
	if db < 0 {
		db = 1 << 30
	}
	return cmpInt(da, db)
}

func pepPhase(v version) int {
	switch {
	case v.pepPre == 0 && v.post < 0 && v.dev >= 0:
		return 0 // X.devN
	case v.pepPre > 0:
		return v.pepPre // a=1, b=2, rc=3
	default:
		return 4 // final (and post releases, ordered by post)
	}
}
