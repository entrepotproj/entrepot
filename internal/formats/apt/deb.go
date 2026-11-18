package apt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// maxControl bounds the size of a package's control file.
const maxControl = 1 << 20

var (
	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionRe = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$`)
	archRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// distRe / componentRe bound distribution and component names (they
	// become path segments).
	distRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	componentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)
)

// field is a deb822 field; Value keeps continuation lines ("\n ...").
type field struct {
	Name  string
	Value string
}

// paragraph is an ordered deb822 paragraph.
type paragraph []field

func (p paragraph) Get(name string) string {
	for _, f := range p {
		if strings.EqualFold(f.Name, name) {
			return strings.TrimSpace(f.Value)
		}
	}
	return ""
}

// Format renders the paragraph, omitting fields named in skip.
func (p paragraph) Format(skip ...string) string {
	var b strings.Builder
	for _, f := range p {
		omit := false
		for _, s := range skip {
			if strings.EqualFold(f.Name, s) {
				omit = true
				break
			}
		}
		if omit {
			continue
		}
		b.WriteString(f.Name)
		b.WriteString(":")
		if f.Value != "" && !strings.HasPrefix(f.Value, "\n") {
			b.WriteString(" ")
		}
		b.WriteString(f.Value)
		b.WriteString("\n")
	}
	return b.String()
}

// parseParagraph parses a single deb822 paragraph (a control file).
func parseParagraph(data string) (paragraph, error) {
	var p paragraph
	for _, line := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			if len(p) > 0 {
				break // end of the first paragraph
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(p) == 0 {
				return nil, errors.New("continuation line before the first field")
			}
			p[len(p)-1].Value += "\n" + line
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, fmt.Errorf("malformed control line %q", line)
		}
		p = append(p, field{Name: name, Value: strings.TrimSpace(value)})
	}
	if len(p) == 0 {
		return nil, errors.New("empty control file")
	}
	return p, nil
}

// readControl extracts ./control from a .deb (an ar archive holding
// debian-binary, control.tar[.gz|.xz|.zst] and data.tar.*).
func readControl(r io.ReaderAt, size int64) ([]byte, error) {
	magic := make([]byte, 8)
	if _, err := r.ReadAt(magic, 0); err != nil || string(magic) != "!<arch>\n" {
		return nil, errors.New("not a Debian package (missing ar header)")
	}
	off := int64(8)
	sawBinary := false
	for off+60 <= size {
		hdr := make([]byte, 60)
		if _, err := r.ReadAt(hdr, off); err != nil {
			return nil, fmt.Errorf("read ar header: %w", err)
		}
		if hdr[58] != '`' || hdr[59] != '\n' {
			return nil, errors.New("corrupt ar member header")
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		n, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || n < 0 || off+60+n > size {
			return nil, errors.New("corrupt ar member size")
		}
		body := io.NewSectionReader(r, off+60, n)
		switch {
		case name == "debian-binary":
			b, _ := io.ReadAll(io.LimitReader(body, 16))
			if !strings.HasPrefix(string(b), "2.") {
				return nil, fmt.Errorf("unsupported Debian package format %q", strings.TrimSpace(string(b)))
			}
			sawBinary = true
		case strings.HasPrefix(name, "control.tar"):
			if !sawBinary {
				return nil, errors.New("debian-binary must be the first member")
			}
			return controlFromTar(body, strings.TrimPrefix(name, "control.tar"))
		}
		off += 60 + n + n%2
	}
	return nil, errors.New("control.tar member not found")
}

func controlFromTar(body io.Reader, ext string) ([]byte, error) {
	var rd io.Reader
	switch ext {
	case "":
		rd = body
	case ".gz":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("control.tar.gz: %w", err)
		}
		defer zr.Close()
		rd = zr
	case ".xz":
		xr, err := xz.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("control.tar.xz: %w", err)
		}
		rd = xr
	case ".zst":
		zr, err := zstd.NewReader(body, zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, fmt.Errorf("control.tar.zst: %w", err)
		}
		defer zr.Close()
		rd = zr
	default:
		return nil, fmt.Errorf("unsupported control archive compression %q", ext)
	}
	tr := tar.NewReader(rd)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("control file not found in control.tar")
		}
		if err != nil {
			return nil, fmt.Errorf("read control.tar: %w", err)
		}
		if strings.TrimPrefix(h.Name, "./") != "control" || h.Typeflag != tar.TypeReg {
			continue
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, io.LimitReader(tr, maxControl+1)); err != nil {
			return nil, err
		}
		if buf.Len() > maxControl {
			return nil, errors.New("control file too large")
		}
		return buf.Bytes(), nil
	}
}

// debInfo is the identifying part of a package's control file.
type debInfo struct {
	Control      paragraph
	Package      string
	Version      string
	Architecture string
}

func parseDeb(r io.ReaderAt, size int64) (*debInfo, error) {
	raw, err := readControl(r, size)
	if err != nil {
		return nil, err
	}
	p, err := parseParagraph(string(raw))
	if err != nil {
		return nil, fmt.Errorf("control file: %w", err)
	}
	d := &debInfo{Control: p, Package: p.Get("Package"), Version: p.Get("Version"), Architecture: p.Get("Architecture")}
	switch {
	case !packageRe.MatchString(d.Package):
		return nil, fmt.Errorf("invalid or missing Package %q", d.Package)
	case !versionRe.MatchString(d.Version):
		return nil, fmt.Errorf("invalid or missing Version %q", d.Version)
	case !archRe.MatchString(d.Architecture):
		return nil, fmt.Errorf("invalid or missing Architecture %q", d.Architecture)
	}
	return d, nil
}

// poolPath is where a package is stored:
// pool/{component}/{prefix}/{package}/{package}_{version}_{arch}.deb with
// the epoch dropped from the file name, as in Debian archives.
func poolPath(component, pkg, version, arch string) string {
	prefix := pkg[:1]
	if strings.HasPrefix(pkg, "lib") && len(pkg) > 3 {
		prefix = pkg[:4]
	}
	return "pool/" + component + "/" + prefix + "/" + pkg + "/" + debFilename(pkg, version, arch)
}

func debFilename(pkg, version, arch string) string {
	if _, v, ok := strings.Cut(version, ":"); ok {
		version = v
	}
	return pkg + "_" + version + "_" + arch + ".deb"
}

// parseDebFilename splits name_version_arch.deb (the version may carry a
// %3a-encoded epoch).
func parseDebFilename(name string) (pkg, version, arch string, ok bool) {
	var base string
	for _, ext := range []string{".deb", ".udeb", ".ddeb"} {
		if strings.HasSuffix(name, ext) {
			base = strings.TrimSuffix(name, ext)
			break
		}
	}
	parts := strings.Split(base, "_")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	version = strings.ReplaceAll(strings.ReplaceAll(parts[1], "%3a", ":"), "%3A", ":")
	return parts[0], version, parts[2], true
}
