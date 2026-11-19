package yum

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

// repoPkg is a package listed in repodata.
type repoPkg struct {
	Info *rpmInfo
	// Href is the package location relative to the repodata root.
	Href     string
	SHA256   string
	Size     int64
	FileTime int64
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func attr(name, value string) string { return " " + name + `="` + esc(value) + `"` }

func versionElem(i *rpmInfo) string {
	return "<version" + attr("epoch", i.Epoch) + attr("ver", i.Version) + attr("rel", i.Release) + "/>"
}

// isPrimaryFile mirrors createrepo_c: files in /etc, any bin/ directory and
// /usr/lib/sendmail are listed in primary.xml as well.
func isPrimaryFile(p string) bool {
	return strings.HasPrefix(p, "/etc/") || strings.Contains(p, "bin/") || p == "/usr/lib/sendmail"
}

func writeFiles(b *bytes.Buffer, indent string, fs []rpmFile, filter func(string) bool) {
	for _, f := range fs {
		if filter != nil && !filter(f.Path) {
			continue
		}
		b.WriteString(indent + "<file")
		if f.Type != "" {
			b.WriteString(attr("type", f.Type))
		}
		b.WriteString(">" + esc(f.Path) + "</file>\n")
	}
}

func writeDeps(b *bytes.Buffer, kind string, ds []rpmDep) {
	if len(ds) == 0 {
		return
	}
	b.WriteString("    <rpm:" + kind + ">\n")
	for _, d := range ds {
		b.WriteString("      <rpm:entry" + attr("name", d.Name))
		if d.Flags != "" {
			b.WriteString(attr("flags", d.Flags))
		}
		if d.Ver != "" {
			b.WriteString(attr("epoch", d.Epoch) + attr("ver", d.Ver))
			if d.Rel != "" {
				b.WriteString(attr("rel", d.Rel))
			}
		}
		if d.Pre {
			b.WriteString(attr("pre", "1"))
		}
		b.WriteString("/>\n")
	}
	b.WriteString("    </rpm:" + kind + ">\n")
}

func primaryXML(pkgs []*repoPkg) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	fmt.Fprintf(&b, "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", len(pkgs))
	for _, p := range pkgs {
		i := p.Info
		b.WriteString("<package type=\"rpm\">\n")
		b.WriteString("  <name>" + esc(i.Name) + "</name>\n")
		b.WriteString("  <arch>" + esc(i.Arch) + "</arch>\n")
		b.WriteString("  " + versionElem(i) + "\n")
		b.WriteString("  <checksum type=\"sha256\" pkgid=\"YES\">" + p.SHA256 + "</checksum>\n")
		b.WriteString("  <summary>" + esc(i.Summary) + "</summary>\n")
		b.WriteString("  <description>" + esc(i.Description) + "</description>\n")
		b.WriteString("  <packager>" + esc(i.Packager) + "</packager>\n")
		b.WriteString("  <url>" + esc(i.URL) + "</url>\n")
		fmt.Fprintf(&b, "  <time file=\"%d\" build=\"%d\"/>\n", p.FileTime, i.BuildTime)
		fmt.Fprintf(&b, "  <size package=\"%d\" installed=\"%d\" archive=\"%d\"/>\n", p.Size, i.InstalledSize, i.ArchiveSize)
		b.WriteString("  <location" + attr("href", p.Href) + "/>\n")
		b.WriteString("  <format>\n")
		b.WriteString("    <rpm:license>" + esc(i.License) + "</rpm:license>\n")
		b.WriteString("    <rpm:vendor>" + esc(i.Vendor) + "</rpm:vendor>\n")
		b.WriteString("    <rpm:group>" + esc(i.Group) + "</rpm:group>\n")
		b.WriteString("    <rpm:buildhost>" + esc(i.BuildHost) + "</rpm:buildhost>\n")
		b.WriteString("    <rpm:sourcerpm>" + esc(i.SourceRPM) + "</rpm:sourcerpm>\n")
		fmt.Fprintf(&b, "    <rpm:header-range start=\"%d\" end=\"%d\"/>\n", i.HeaderStart, i.HeaderEnd)
		writeDeps(&b, "provides", i.Provides)
		writeDeps(&b, "requires", i.Requires)
		writeDeps(&b, "conflicts", i.Conflicts)
		writeDeps(&b, "obsoletes", i.Obsoletes)
		writeDeps(&b, "suggests", i.Suggests)
		writeDeps(&b, "enhances", i.Enhances)
		writeDeps(&b, "recommends", i.Recommends)
		writeDeps(&b, "supplements", i.Supplements)
		writeFiles(&b, "    ", i.Files, isPrimaryFile)
		b.WriteString("  </format>\n")
		b.WriteString("</package>\n")
	}
	b.WriteString("</metadata>\n")
	return b.Bytes()
}

func filelistsXML(pkgs []*repoPkg) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	fmt.Fprintf(&b, "<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"%d\">\n", len(pkgs))
	for _, p := range pkgs {
		i := p.Info
		b.WriteString("<package" + attr("pkgid", p.SHA256) + attr("name", i.Name) + attr("arch", i.Arch) + ">\n")
		b.WriteString("  " + versionElem(i) + "\n")
		writeFiles(&b, "  ", i.Files, nil)
		b.WriteString("</package>\n")
	}
	b.WriteString("</filelists>\n")
	return b.Bytes()
}

func otherXML(pkgs []*repoPkg) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	fmt.Fprintf(&b, "<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"%d\">\n", len(pkgs))
	for _, p := range pkgs {
		i := p.Info
		b.WriteString("<package" + attr("pkgid", p.SHA256) + attr("name", i.Name) + attr("arch", i.Arch) + ">\n")
		b.WriteString("  " + versionElem(i) + "\n")
		for _, c := range i.Changelogs {
			fmt.Fprintf(&b, "  <changelog%s date=\"%d\">%s</changelog>\n", attr("author", c.Author), c.Date, esc(c.Text))
		}
		b.WriteString("</package>\n")
	}
	b.WriteString("</otherdata>\n")
	return b.Bytes()
}

// mdFile is a compressed repodata file referenced from repomd.xml.
type mdFile struct {
	Type         string
	Name         string // {sha256}-{type}.xml.gz
	Data         []byte // compressed
	Checksum     string
	OpenChecksum string
	OpenSize     int
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newMDFile(typ string, open []byte) mdFile {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(open)
	_ = zw.Close()
	c := sum(buf.Bytes())
	return mdFile{Type: typ, Name: c + "-" + typ + ".xml.gz", Data: buf.Bytes(), Checksum: c, OpenChecksum: sum(open), OpenSize: len(open)}
}

func repomdXML(files []mdFile, revision int64) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString("<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n")
	fmt.Fprintf(&b, "  <revision>%d</revision>\n", revision)
	for _, f := range files {
		fmt.Fprintf(&b, "  <data type=\"%s\">\n", f.Type)
		fmt.Fprintf(&b, "    <checksum type=\"sha256\">%s</checksum>\n", f.Checksum)
		fmt.Fprintf(&b, "    <open-checksum type=\"sha256\">%s</open-checksum>\n", f.OpenChecksum)
		fmt.Fprintf(&b, "    <location href=\"repodata/%s\"/>\n", f.Name)
		fmt.Fprintf(&b, "    <timestamp>%d</timestamp>\n", revision)
		fmt.Fprintf(&b, "    <size>%d</size>\n", len(f.Data))
		fmt.Fprintf(&b, "    <open-size>%d</open-size>\n", f.OpenSize)
		b.WriteString("  </data>\n")
	}
	b.WriteString("</repomd>\n")
	return b.Bytes()
}

// repomdLocations extracts the <location href> values of a repomd.xml.
func repomdLocations(b []byte) []string {
	var doc struct {
		Data []struct {
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if xml.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []string
	for _, d := range doc.Data {
		if d.Location.Href != "" {
			out = append(out, d.Location.Href)
		}
	}
	return out
}
