package npm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// packument is a package document. Unknown fields are preserved verbatim.
type packument struct {
	Fields   map[string]json.RawMessage
	Versions map[string]map[string]json.RawMessage
	DistTags map[string]string
	Time     map[string]json.RawMessage
}

func newPackument(name string) *packument {
	n, _ := json.Marshal(name)
	return &packument{
		Fields:   map[string]json.RawMessage{"_id": n, "name": n},
		Versions: map[string]map[string]json.RawMessage{},
		DistTags: map[string]string{},
		Time:     map[string]json.RawMessage{},
	}
}

func parsePackument(b []byte) (*packument, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("invalid packument: %w", err)
	}
	p := &packument{Fields: raw, Versions: map[string]map[string]json.RawMessage{}, DistTags: map[string]string{}, Time: map[string]json.RawMessage{}}
	if v, ok := raw["versions"]; ok {
		var vs map[string]json.RawMessage
		if err := json.Unmarshal(v, &vs); err != nil {
			return nil, fmt.Errorf("invalid packument versions: %w", err)
		}
		for ver, m := range vs {
			var man map[string]json.RawMessage
			if json.Unmarshal(m, &man) == nil && man != nil {
				p.Versions[ver] = man
			}
		}
	}
	if v, ok := raw["dist-tags"]; ok {
		var tags map[string]json.RawMessage
		_ = json.Unmarshal(v, &tags)
		for t, rv := range tags {
			var s string
			if json.Unmarshal(rv, &s) == nil {
				p.DistTags[t] = s
			}
		}
	}
	if v, ok := raw["time"]; ok {
		_ = json.Unmarshal(v, &p.Time)
		if p.Time == nil {
			p.Time = map[string]json.RawMessage{}
		}
	}
	delete(raw, "versions")
	delete(raw, "dist-tags")
	delete(raw, "time")
	return p, nil
}

func marshal(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // only marshals values built from valid JSON
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func (p *packument) doc() map[string]any {
	out := make(map[string]any, len(p.Fields)+3)
	for k, v := range p.Fields {
		out[k] = v
	}
	out["versions"] = p.Versions
	out["dist-tags"] = p.DistTags
	if len(p.Time) > 0 {
		out["time"] = p.Time
	}
	return out
}

func (p *packument) bytes() []byte { return marshal(p.doc()) }

func (p *packument) str(field string) string {
	var s string
	_ = json.Unmarshal(p.Fields[field], &s)
	return s
}

func (p *packument) setStr(field, v string) { p.Fields[field] = marshal(v) }

func rawStr(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}

func dist(man map[string]json.RawMessage) map[string]json.RawMessage {
	var d map[string]json.RawMessage
	_ = json.Unmarshal(man["dist"], &d)
	if d == nil {
		d = map[string]json.RawMessage{}
	}
	return d
}

// tarballFile returns the file name of a version's tarball.
func tarballFile(name, version string, man map[string]json.RawMessage) string {
	t := rawStr(dist(man), "tarball")
	if t != "" {
		if u, err := url.Parse(t); err == nil {
			t = u.Path
		}
		if i := strings.LastIndex(t, "/"); i >= 0 {
			t = t[i+1:]
		}
		if f, err := url.PathUnescape(t); err == nil {
			t = f
		}
	}
	if t == "" || !validFile(t) {
		t = unscoped(name) + "-" + version + ".tgz"
	}
	return t
}

func validFile(f string) bool {
	return f != "" && f != "." && f != ".." && len(f) <= 255 && !strings.ContainsAny(f, "/\\\x00")
}

// pkgURL is the URL path of a package below a repository URL.
func pkgURL(name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// rewrite points every dist.tarball at repoURL (".../repository/{repo}/").
func (p *packument) rewrite(repoURL, name string) {
	for v, man := range p.Versions {
		d := dist(man)
		file := tarballFile(name, v, man)
		d["tarball"] = marshal(repoURL + pkgURL(name) + "/-/" + url.PathEscape(file))
		man["dist"] = marshal(d)
	}
}

// abbreviatedFields are kept in abbreviated ("corgi") version manifests.
var abbreviatedFields = []string{
	"name", "version", "deprecated", "dependencies", "optionalDependencies", "devDependencies",
	"bundleDependencies", "bundledDependencies", "peerDependencies", "peerDependenciesMeta",
	"acceptDependencies", "bin", "directories", "dist", "engines", "_hasShrinkwrap",
	"hasInstallScript", "cpu", "os", "libc", "funding",
}

func (p *packument) abbreviated() map[string]any {
	versions := make(map[string]map[string]json.RawMessage, len(p.Versions))
	for v, man := range p.Versions {
		a := map[string]json.RawMessage{}
		for _, f := range abbreviatedFields {
			if x, ok := man[f]; ok {
				a[f] = x
			}
		}
		if _, ok := man["scripts"]; ok && hasInstallScript(man) {
			a["hasInstallScript"] = json.RawMessage("true")
		}
		versions[v] = a
	}
	out := map[string]any{"name": p.Fields["name"], "dist-tags": p.DistTags, "versions": versions}
	if m, ok := p.Time["modified"]; ok {
		out["modified"] = m
	} else if m, ok := p.Fields["modified"]; ok {
		out["modified"] = m
	}
	return out
}

func hasInstallScript(man map[string]json.RawMessage) bool {
	if string(man["hasInstallScript"]) == "true" {
		return true
	}
	var scripts map[string]json.RawMessage
	_ = json.Unmarshal(man["scripts"], &scripts)
	for _, s := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := scripts[s]; ok {
			return true
		}
	}
	return false
}

// fixTags drops dist-tags pointing at missing versions and makes sure
// "latest" exists while there are versions.
func (p *packument) fixTags() {
	for t, v := range p.DistTags {
		if _, ok := p.Versions[v]; !ok {
			delete(p.DistTags, t)
		}
	}
	if _, ok := p.DistTags["latest"]; !ok && len(p.Versions) > 0 {
		p.DistTags["latest"] = p.highest()
	}
}

// highest returns the highest version, preferring releases.
func (p *packument) highest() string {
	vs := make([]string, 0, len(p.Versions))
	for v := range p.Versions {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return compareSemver(vs[i], vs[j]) < 0 })
	best := ""
	for _, v := range vs {
		if !strings.Contains(v, "-") {
			best = v
		}
	}
	if best == "" && len(vs) > 0 {
		best = vs[len(vs)-1]
	}
	return best
}

func (p *packument) nextRev() string {
	n := 0
	if r := p.str("_rev"); r != "" {
		n, _ = strconv.Atoi(strings.SplitN(r, "-", 2)[0])
	}
	sum := sha256.Sum256(p.bytes())
	return strconv.Itoa(n+1) + "-" + hex.EncodeToString(sum[:8])
}

// compareSemver compares two versions (semver with a lenient fallback).
func compareSemver(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	for i := 0; i < 3; i++ {
		if pa.nums[i] != pb.nums[i] {
			if pa.nums[i] < pb.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa.pre == "" && pb.pre == "":
		return strings.Compare(a, b)
	case pa.pre == "":
		return 1
	case pb.pre == "":
		return -1
	}
	ia, ib := strings.Split(pa.pre, "."), strings.Split(pb.pre, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		na, ea := strconv.Atoi(ia[i])
		nb, eb := strconv.Atoi(ib[i])
		switch {
		case ea == nil && eb == nil && na != nb:
			if na < nb {
				return -1
			}
			return 1
		case ea == nil && eb != nil:
			return -1
		case ea != nil && eb == nil:
			return 1
		case ia[i] != ib[i]:
			return strings.Compare(ia[i], ib[i])
		}
	}
	return len(ia) - len(ib)
}

type semver struct {
	nums [3]int
	pre  string
}

func parseSemver(v string) semver {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var s semver
	core := v
	if i := strings.IndexByte(v, '-'); i >= 0 {
		core, s.pre = v[:i], v[i+1:]
	}
	for i, part := range strings.SplitN(core, ".", 3) {
		s.nums[i], _ = strconv.Atoi(part)
	}
	return s
}
