package pypi

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const metadataSuffix = ".metadata"

var (
	separators = regexp.MustCompile(`[-_.]+`)
	nameRe     = regexp.MustCompile(`^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$`)
	versionRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]*$`)
)

// Normalize returns the PEP 503 normalised project name.
func Normalize(name string) string {
	return strings.ToLower(separators.ReplaceAllString(name, "-"))
}

// ValidName reports whether name is a valid (PEP 508) project name.
func ValidName(name string) bool { return len(name) <= 200 && nameRe.MatchString(name) }

func validVersion(v string) bool { return len(v) <= 128 && versionRe.MatchString(v) }

const (
	kindWheel = "bdist_wheel"
	kindEgg   = "bdist_egg"
	kindSdist = "sdist"
)

var sdistExts = []string{".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar"}

// parseFilename extracts the project name and version from a distribution
// filename. project, when known, disambiguates sdist names containing
// hyphens ("python-dateutil-2.8.2.tar.gz").
func parseFilename(filename, project string) (name, version, kind string, ok bool) {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".whl"):
		parts := strings.Split(filename[:len(filename)-4], "-")
		if len(parts) != 5 && len(parts) != 6 {
			return "", "", "", false
		}
		return parts[0], parts[1], kindWheel, parts[0] != "" && parts[1] != ""
	case strings.HasSuffix(lower, ".egg"):
		parts := strings.Split(filename[:len(filename)-4], "-")
		if len(parts) < 2 {
			return "", "", "", false
		}
		return parts[0], parts[1], kindEgg, parts[0] != "" && parts[1] != ""
	}
	for _, ext := range sdistExts {
		if !strings.HasSuffix(lower, ext) {
			continue
		}
		stem := filename[:len(filename)-len(ext)]
		if project != "" {
			for i := 0; i < len(stem); i++ {
				if stem[i] == '-' && Normalize(stem[:i]) == project && i+1 < len(stem) {
					return stem[:i], stem[i+1:], kindSdist, true
				}
			}
		}
		// The version starts at the first hyphen followed by a digit.
		for i := 0; i+1 < len(stem); i++ {
			if stem[i] == '-' && stem[i+1] >= '0' && stem[i+1] <= '9' && i > 0 {
				return stem[:i], stem[i+1:], kindSdist, true
			}
		}
		return "", "", "", false
	}
	return "", "", "", false
}

// filePath is a parsed packages/{project}/{version}/{filename} path.
type filePath struct {
	Project, Version, Filename string
	// Dist is the distribution filename (Filename without .metadata).
	Dist     string
	Metadata bool
}

func parseFilePath(p string) (filePath, bool) {
	segs := strings.Split(p, "/")
	if len(segs) != 4 || segs[0] != "packages" || segs[3] == "" {
		return filePath{}, false
	}
	fp := filePath{Project: segs[1], Version: segs[2], Filename: segs[3], Dist: segs[3]}
	if strings.HasSuffix(fp.Filename, metadataSuffix) {
		fp.Metadata = true
		fp.Dist = strings.TrimSuffix(fp.Filename, metadataSuffix)
	}
	if Normalize(fp.Project) != fp.Project || !ValidName(fp.Project) {
		return filePath{}, false
	}
	return fp, true
}

// filePathFor returns the repository path for a distribution file.
func filePathFor(project, version, filename string) string {
	if version == "" || !validVersion(version) {
		version = "unknown"
	}
	return "packages/" + project + "/" + version + "/" + filename
}

func contentType(filename string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, metadataSuffix):
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(lower, ".whl"), strings.HasSuffix(lower, ".zip"), strings.HasSuffix(lower, ".egg"):
		return "application/zip"
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "application/gzip"
	case strings.HasSuffix(lower, ".tar.bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(lower, ".tar.xz"):
		return "application/x-xz"
	}
	return "application/octet-stream"
}

// validFilename rejects names that cannot be a single path segment.
func validFilename(f string) bool {
	if f == "" || len(f) > 255 || f == "." || f == ".." || strings.ContainsAny(f, "/\\") {
		return false
	}
	for _, c := range f {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// metadata is the subset of core metadata Entrepot records.
type metadata struct {
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"`
	Summary        string `json:"summary,omitempty"`
	Description    string `json:"description,omitempty"`
	RequiresPython string `json:"requires_python,omitempty"`
	Author         string `json:"author,omitempty"`
	AuthorEmail    string `json:"author_email,omitempty"`
	License        string `json:"license,omitempty"`
	HomePage       string `json:"home_page,omitempty"`
	Keywords       string `json:"keywords,omitempty"`
}

// merge fills empty fields of m from o.
func (m *metadata) merge(o *metadata) {
	if o == nil {
		return
	}
	fill := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	fill(&m.Name, o.Name)
	fill(&m.Version, o.Version)
	fill(&m.Summary, o.Summary)
	fill(&m.Description, o.Description)
	fill(&m.RequiresPython, o.RequiresPython)
	fill(&m.Author, o.Author)
	fill(&m.AuthorEmail, o.AuthorEmail)
	fill(&m.License, o.License)
	fill(&m.HomePage, o.HomePage)
	fill(&m.Keywords, o.Keywords)
}

// parseMetadata parses an RFC 822 style METADATA / PKG-INFO document.
func parseMetadata(b []byte) *metadata {
	m := &metadata{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var key, val string
	var body strings.Builder
	inBody := false
	flush := func() {
		if key == "" {
			return
		}
		v := strings.TrimSpace(val)
		switch strings.ToLower(key) {
		case "name":
			m.Name = v
		case "version":
			m.Version = v
		case "summary":
			m.Summary = v
		case "description":
			m.Description = v
		case "requires-python":
			m.RequiresPython = v
		case "author":
			m.Author = v
		case "author-email":
			m.AuthorEmail = v
		case "license":
			m.License = v
		case "home-page":
			m.HomePage = v
		case "keywords":
			m.Keywords = v
		}
		key, val = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if inBody {
			body.WriteString(line)
			body.WriteByte('\n')
			continue
		}
		if line == "" {
			flush()
			inBody = true
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && key != "" {
			val += "\n" + strings.TrimSpace(line)
			continue
		}
		flush()
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = k, v
	}
	flush()
	if d := strings.TrimSpace(body.String()); d != "" && m.Description == "" {
		m.Description = d
	}
	return m
}

const maxMetadataSize = 16 << 20

var errNoMetadata = errors.New("no metadata file found")

// wheelMetadata returns the *.dist-info/METADATA file of a wheel.
func wheelMetadata(ra io.ReaderAt, size int64, name, version string) ([]byte, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("not a zip archive: %w", err)
	}
	var candidates []*zip.File
	for _, f := range zr.File {
		dir, base := path.Split(f.Name)
		if base == "METADATA" && strings.Count(dir, "/") == 1 && strings.HasSuffix(dir, ".dist-info/") {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return nil, errNoMetadata
	}
	pick := candidates[0]
	want := strings.ToLower(name + "-" + version + ".dist-info/")
	for _, f := range candidates {
		if strings.HasPrefix(strings.ToLower(f.Name), want) {
			pick = f
		}
	}
	return readZipFile(pick)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxMetadataSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetadataSize {
		return nil, errors.New("metadata file too large")
	}
	return b, nil
}

// sdistMetadata returns the top-level PKG-INFO of a .tar.gz or .zip sdist.
func sdistMetadata(ra io.ReaderAt, size int64, filename string) ([]byte, error) {
	isPkgInfo := func(name string) bool {
		name = strings.TrimPrefix(name, "./")
		dir, base := path.Split(name)
		return base == "PKG-INFO" && strings.Count(dir, "/") == 1
	}
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		zr, err := zip.NewReader(ra, size)
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if isPkgInfo(f.Name) {
				return readZipFile(f)
			}
		}
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(io.NewSectionReader(ra, 0, size))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err != nil {
				return nil, err
			}
			if hdr.Typeflag == tar.TypeReg && isPkgInfo(hdr.Name) {
				b, err := io.ReadAll(io.LimitReader(tr, maxMetadataSize+1))
				if err != nil {
					return nil, err
				}
				if len(b) > maxMetadataSize {
					return nil, errors.New("PKG-INFO too large")
				}
				return b, nil
			}
		}
	}
	return nil, errNoMetadata
}
