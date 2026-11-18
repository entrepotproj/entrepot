package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/geoffo-dev/package-repository/internal/format"
)

// chartMeta is the subset of Chart.yaml published in index.yaml. Field
// names follow Helm's chart.Metadata (Helm reads index files strictly, so
// unknown fields must not be emitted).
type chartMeta struct {
	APIVersion   string            `yaml:"apiVersion" json:"apiVersion"`
	Name         string            `yaml:"name" json:"name"`
	Version      string            `yaml:"version" json:"version"`
	KubeVersion  string            `yaml:"kubeVersion,omitempty" json:"kubeVersion,omitempty"`
	Description  string            `yaml:"description,omitempty" json:"description,omitempty"`
	Type         string            `yaml:"type,omitempty" json:"type,omitempty"`
	Keywords     []string          `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	Home         string            `yaml:"home,omitempty" json:"home,omitempty"`
	Sources      []string          `yaml:"sources,omitempty" json:"sources,omitempty"`
	Dependencies []*dependency     `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
	Maintainers  []*maintainer     `yaml:"maintainers,omitempty" json:"maintainers,omitempty"`
	Icon         string            `yaml:"icon,omitempty" json:"icon,omitempty"`
	AppVersion   string            `yaml:"appVersion,omitempty" json:"appVersion,omitempty"`
	Deprecated   bool              `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	Annotations  map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	Condition    string            `yaml:"condition,omitempty" json:"condition,omitempty"`
	Tags         string            `yaml:"tags,omitempty" json:"tags,omitempty"`
}

type maintainer struct {
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
	URL   string `yaml:"url,omitempty" json:"url,omitempty"`
}

type dependency struct {
	Name         string   `yaml:"name" json:"name"`
	Version      string   `yaml:"version,omitempty" json:"version,omitempty"`
	Repository   string   `yaml:"repository,omitempty" json:"repository,omitempty"`
	Condition    string   `yaml:"condition,omitempty" json:"condition,omitempty"`
	Tags         []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Enabled      bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	ImportValues []any    `yaml:"import-values,omitempty" json:"import-values,omitempty"`
	Alias        string   `yaml:"alias,omitempty" json:"alias,omitempty"`
}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,249}$`)
	// semverRe accepts the versions Helm accepts (Masterminds semver):
	// an optional "v", 1-3 numeric parts, pre-release and build metadata.
	semverRe = regexp.MustCompile(`^v?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?(\.(0|[1-9][0-9]*))?` +
		`(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

func validName(n string) bool    { return nameRe.MatchString(n) && !strings.Contains(n, "..") }
func validVersion(v string) bool { return len(v) <= 128 && semverRe.MatchString(v) }

// chartFile is the canonical package file name.
func chartFile(name, version string) string { return name + "-" + version + ".tgz" }

// maxChartYAML bounds Chart.yaml.
const maxChartYAML = 1 << 20

// parseChart reads {chart}/Chart.yaml from a packaged chart and validates it.
func parseChart(b []byte) (*chartMeta, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, format.BadRequest("not a gzip-compressed chart archive: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, format.BadRequest("chart archive has no Chart.yaml")
		}
		if err != nil {
			return nil, format.BadRequest("invalid chart archive: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA in old archives
			continue
		}
		p := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		segs := strings.Split(p, "/")
		if len(segs) != 2 || segs[1] != "Chart.yaml" {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, maxChartYAML+1))
		if err != nil {
			return nil, format.BadRequest("invalid chart archive: %v", err)
		}
		if len(raw) > maxChartYAML {
			return nil, format.BadRequest("Chart.yaml is too large")
		}
		return parseChartYAML(raw)
	}
}

func parseChartYAML(raw []byte) (*chartMeta, error) {
	var m chartMeta
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, format.BadRequest("invalid Chart.yaml: %v", err)
	}
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	switch {
	case m.Name == "":
		return nil, format.BadRequest("Chart.yaml: name is required")
	case !validName(m.Name):
		return nil, format.BadRequest("Chart.yaml: invalid chart name %q", m.Name)
	case m.Version == "":
		return nil, format.BadRequest("Chart.yaml: version is required")
	case !validVersion(m.Version):
		return nil, format.BadRequest("Chart.yaml: version %q is not a valid semantic version", m.Version)
	}
	if m.APIVersion == "" {
		m.APIVersion = "v1"
	}
	if m.APIVersion != "v1" && m.APIVersion != "v2" {
		return nil, format.BadRequest("Chart.yaml: unsupported apiVersion %q", m.APIVersion)
	}
	return &m, nil
}

// metaMap converts metadata to the generic form used for index entries.
func (m *chartMeta) metaMap() map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// ---- versions ----

type semver struct {
	nums [3]int
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	if !semverRe.MatchString(v) {
		return semver{}, false
	}
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var s semver
	core, pre, hasPre := strings.Cut(v, "-")
	if hasPre {
		s.pre = strings.Split(pre, ".")
	}
	for i, p := range strings.Split(core, ".") {
		if i < 3 {
			s.nums[i], _ = strconv.Atoi(p)
		}
	}
	return s, true
}

// compareVersions orders chart versions by SemVer precedence; versions
// that do not parse sort before those that do, then lexically.
func compareVersions(a, b string) int {
	pa, oka := parseSemver(a)
	pb, okb := parseSemver(b)
	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa.nums[i] != pb.nums[i] {
			if pa.nums[i] < pb.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return strings.Compare(a, b)
	case len(pa.pre) == 0:
		return 1
	case len(pb.pre) == 0:
		return -1
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		na, ea := strconv.Atoi(pa.pre[i])
		nb, eb := strconv.Atoi(pb.pre[i])
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
		case pa.pre[i] != pb.pre[i]:
			return strings.Compare(pa.pre[i], pb.pre[i])
		}
	}
	return len(pa.pre) - len(pb.pre)
}

// provFiles extracts "{file}.tgz" names from the files section of a
// provenance file.
var provFileRe = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._+-]*\.tgz):\s*sha256:[0-9a-fA-F]{64}\s*$`)

func provChartFile(b []byte) string {
	if m := provFileRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
