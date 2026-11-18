package yum

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"
)

// hdrBuilder writes RPM header structures for tests.
type hdrBuilder struct {
	entries []struct{ tag, typ, off, count uint32 }
	store   bytes.Buffer
}

func (b *hdrBuilder) align(n int) {
	for b.store.Len()%n != 0 {
		b.store.WriteByte(0)
	}
}

func (b *hdrBuilder) add(tag, typ, count uint32, data []byte, align int) {
	b.align(align)
	b.entries = append(b.entries, struct{ tag, typ, off, count uint32 }{tag, typ, uint32(b.store.Len()), count})
	b.store.Write(data)
}

func (b *hdrBuilder) str(tag uint32, s string) { b.add(tag, typeString, 1, append([]byte(s), 0), 1) }

func (b *hdrBuilder) strs(tag uint32, ss ...string) {
	var d []byte
	for _, s := range ss {
		d = append(append(d, s...), 0)
	}
	b.add(tag, typeStringArray, uint32(len(ss)), d, 1)
}

func (b *hdrBuilder) i32(tag uint32, vs ...uint32) {
	d := make([]byte, 4*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint32(d[4*i:], v)
	}
	b.add(tag, typeInt32, uint32(len(vs)), d, 4)
}

func (b *hdrBuilder) i16(tag uint32, vs ...uint16) {
	d := make([]byte, 2*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint16(d[2*i:], v)
	}
	b.add(tag, typeInt16, uint32(len(vs)), d, 2)
}

func (b *hdrBuilder) bytes() []byte {
	sort.Slice(b.entries, func(i, j int) bool { return b.entries[i].tag < b.entries[j].tag })
	var out bytes.Buffer
	out.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	_ = binary.Write(&out, binary.BigEndian, uint32(len(b.entries)))
	_ = binary.Write(&out, binary.BigEndian, uint32(b.store.Len()))
	for _, e := range b.entries {
		_ = binary.Write(&out, binary.BigEndian, []uint32{e.tag, e.typ, e.off, e.count})
	}
	out.Write(b.store.Bytes())
	return out.Bytes()
}

// BuildTestRPM assembles a minimal binary RPM (lead, signature header,
// header and an opaque payload).
func BuildTestRPM(name, epoch, version, release, arch string, payload []byte) []byte {
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	copy(lead[10:], name+"-"+version+"-"+release)
	binary.BigEndian.PutUint16(lead[78:], 5) // signature type: header-style

	var sig hdrBuilder
	sig.i32(sigTagPayloadSize, uint32(len(payload)))
	sigBytes := sig.bytes()
	for len(sigBytes)%8 != 0 {
		sigBytes = append(sigBytes, 0)
	}

	var h hdrBuilder
	h.str(tagName, name)
	h.str(tagVersion, version)
	h.str(tagRelease, release)
	if epoch != "" {
		var e uint32
		for _, c := range epoch {
			e = e*10 + uint32(c-'0')
		}
		h.i32(tagEpoch, e)
	}
	h.str(tagSummary, "Test package "+name)
	h.str(tagDescription, "A package <for> tests & such.")
	h.i32(tagBuildTime, 1700000000)
	h.str(tagBuildHost, "builder.example.com")
	h.i32(tagSize, 1234)
	h.str(tagLicense, "MIT")
	h.str(tagGroup, "Unspecified")
	h.str(tagURL, "https://example.com/"+name)
	h.str(tagArch, arch)
	h.str(tagSourceRPM, name+"-"+version+"-"+release+".src.rpm")
	evr := version + "-" + release
	if epoch != "" {
		evr = epoch + ":" + evr
	}
	h.strs(tagProvideName, name, name+"("+arch+")")
	h.i32(tagProvideFlags, senseEqual, senseEqual)
	h.strs(tagProvideVer, evr, evr)
	h.strs(tagRequireName, "/bin/sh", "rpmlib(CompressedFileNames)", "libc.so.6()(64bit)", "bash")
	h.i32(tagRequireFlags, senseScriptPre, senseRPMLib|senseLess|senseEqual, 0, senseGreater|senseEqual)
	h.strs(tagRequireVer, "", "3.0.4-1", "", "4.0")
	h.strs(tagDirNames, "/usr/bin/", "/usr/share/doc/"+name+"/", "/etc/")
	h.strs(tagBaseNames, name, "README", name+".conf")
	h.i32(tagDirIndexes, 0, 1, 2)
	h.i16(tagFileModes, 0o100755, 0o100644, 0o100644)
	h.i32(tagFileFlags, 0, 0, fileGhost)
	h.i32(tagChangelogTime, 1700000000, 1600000000)
	h.strs(tagChangelogName, "Dev <dev@example.com> - "+evr, "Dev <dev@example.com> - 0.1-1")
	h.strs(tagChangelogText, "- newest", "- oldest")

	var out bytes.Buffer
	out.Write(lead)
	out.Write(sigBytes)
	out.Write(h.bytes())
	out.Write(payload)
	return out.Bytes()
}

func TestParseRPM(t *testing.T) {
	b := BuildTestRPM("hello", "2", "1.0", "1.el9", "x86_64", []byte("payload"))
	info, err := parseRPM(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "hello" || info.Epoch != "2" || info.Version != "1.0" || info.Release != "1.el9" || info.Arch != "x86_64" {
		t.Fatalf("nevra: %+v", info)
	}
	if info.EVR() != "2:1.0-1.el9" || info.ArchiveSize != 7 || info.InstalledSize != 1234 || info.BuildTime != 1700000000 {
		t.Fatalf("info: %+v", info)
	}
	if info.HeaderStart%8 != 0 || info.HeaderStart <= 96 {
		t.Fatalf("header start %d", info.HeaderStart)
	}
	if info.HeaderEnd != int64(len(b)-7) {
		t.Fatalf("header end %d, want %d", info.HeaderEnd, len(b)-7)
	}
	if len(info.Requires) != 3 || !info.Requires[0].Pre || info.Requires[2].Flags != "GE" || info.Requires[2].Ver != "4.0" {
		t.Fatalf("requires: %+v", info.Requires)
	}
	if p := info.Provides[0]; p.Flags != "EQ" || p.Epoch != "2" || p.Ver != "1.0" || p.Rel != "1.el9" {
		t.Fatalf("provides: %+v", info.Provides)
	}
	if len(info.Files) != 3 || info.Files[0].Path != "/usr/bin/hello" || info.Files[2].Type != "ghost" {
		t.Fatalf("files: %+v", info.Files)
	}
	if len(info.Changelogs) != 2 || info.Changelogs[0].Text != "- oldest" {
		t.Fatalf("changelogs: %+v", info.Changelogs)
	}
	if _, err := parseRPM(bytes.NewReader([]byte("nope")), 4); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestParseRPMFilename(t *testing.T) {
	n, v, a, ok := parseRPMFilename("python3-libs-3.9.18-3.el9.x86_64.rpm")
	if !ok || n != "python3-libs" || v != "3.9.18-3.el9" || a != "x86_64" {
		t.Fatalf("%s %s %s %v", n, v, a, ok)
	}
	if _, _, _, ok := parseRPMFilename("foo.rpm"); ok {
		t.Fatal("foo.rpm parsed")
	}
}
