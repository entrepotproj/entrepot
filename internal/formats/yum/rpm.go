package yum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// RPM header tags (rpmtag.h).
const (
	tagName          = 1000
	tagVersion       = 1001
	tagRelease       = 1002
	tagEpoch         = 1003
	tagSummary       = 1004
	tagDescription   = 1005
	tagBuildTime     = 1006
	tagBuildHost     = 1007
	tagSize          = 1009
	tagVendor        = 1011
	tagLicense       = 1014
	tagPackager      = 1015
	tagGroup         = 1016
	tagURL           = 1020
	tagArch          = 1022
	tagOldFilenames  = 1027
	tagFileModes     = 1030
	tagFileFlags     = 1037
	tagSourceRPM     = 1044
	tagArchiveSize   = 1046
	tagProvideName   = 1047
	tagRequireFlags  = 1048
	tagRequireName   = 1049
	tagRequireVer    = 1050
	tagConflictFlags = 1053
	tagConflictName  = 1054
	tagConflictVer   = 1055
	tagChangelogTime = 1080
	tagChangelogName = 1081
	tagChangelogText = 1082
	tagObsoleteName  = 1090
	tagSourcePackage = 1106
	tagProvideFlags  = 1112
	tagProvideVer    = 1113
	tagObsoleteFlags = 1114
	tagObsoleteVer   = 1115
	tagDirIndexes    = 1116
	tagBaseNames     = 1117
	tagDirNames      = 1118
	tagLongSize      = 5009
	tagRecommendName = 5046
	tagRecommendVer  = 5047
	tagRecommendFlg  = 5048
	tagSuggestName   = 5049
	tagSuggestVer    = 5050
	tagSuggestFlg    = 5051
	tagSupplementNam = 5052
	tagSupplementVer = 5053
	tagSupplementFlg = 5054
	tagEnhanceName   = 5055
	tagEnhanceVer    = 5056
	tagEnhanceFlg    = 5057

	// Signature header tags.
	sigTagPayloadSize     = 1007
	sigTagLongArchiveSize = 271
)

// Header value types.
const (
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

// Dependency flags (rpmds.h).
const (
	senseLess       = 0x02
	senseGreater    = 0x04
	senseEqual      = 0x08
	sensePreReq     = 0x40
	senseScriptPre  = 0x200
	senseScriptPost = 0x400
	senseRPMLib     = 0x1000000

	fileGhost = 0x40
)

var (
	rpmNameRe = regexp.MustCompile(`^[A-Za-z0-9_+.-]+$`)
	rpmVerRe  = regexp.MustCompile(`^[A-Za-z0-9._+~^]+$`)
	rpmArchRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// rpmDep is a provides/requires/... entry.
type rpmDep struct {
	Name  string `json:"name"`
	Flags string `json:"flags,omitempty"` // EQ, LT, GT, LE, GE
	Epoch string `json:"epoch,omitempty"`
	Ver   string `json:"ver,omitempty"`
	Rel   string `json:"rel,omitempty"`
	Pre   bool   `json:"pre,omitempty"`
}

type rpmFile struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"` // "", dir, ghost
}

type rpmChangelog struct {
	Author string `json:"author"`
	Date   int64  `json:"date"`
	Text   string `json:"text"`
}

// rpmInfo is the repodata-relevant content of an RPM header. It is stored
// in the asset attributes, so repodata generation never reads packages.
type rpmInfo struct {
	Name          string         `json:"name"`
	Epoch         string         `json:"epoch"`
	Version       string         `json:"version"`
	Release       string         `json:"release"`
	Arch          string         `json:"arch"`
	Summary       string         `json:"summary"`
	Description   string         `json:"description"`
	Packager      string         `json:"packager,omitempty"`
	URL           string         `json:"url,omitempty"`
	License       string         `json:"license,omitempty"`
	Vendor        string         `json:"vendor,omitempty"`
	Group         string         `json:"group,omitempty"`
	BuildHost     string         `json:"buildhost,omitempty"`
	SourceRPM     string         `json:"sourcerpm,omitempty"`
	BuildTime     int64          `json:"buildtime"`
	InstalledSize int64          `json:"installedSize"`
	ArchiveSize   int64          `json:"archiveSize"`
	HeaderStart   int64          `json:"headerStart"`
	HeaderEnd     int64          `json:"headerEnd"`
	Provides      []rpmDep       `json:"provides,omitempty"`
	Requires      []rpmDep       `json:"requires,omitempty"`
	Conflicts     []rpmDep       `json:"conflicts,omitempty"`
	Obsoletes     []rpmDep       `json:"obsoletes,omitempty"`
	Recommends    []rpmDep       `json:"recommends,omitempty"`
	Suggests      []rpmDep       `json:"suggests,omitempty"`
	Supplements   []rpmDep       `json:"supplements,omitempty"`
	Enhances      []rpmDep       `json:"enhances,omitempty"`
	Files         []rpmFile      `json:"files,omitempty"`
	Changelogs    []rpmChangelog `json:"changelogs,omitempty"`
}

// EVR returns [epoch:]version-release.
func (i *rpmInfo) EVR() string {
	v := i.Version + "-" + i.Release
	if i.Epoch != "" && i.Epoch != "0" {
		v = i.Epoch + ":" + v
	}
	return v
}

// NEVRA returns name-[epoch:]version-release.arch.
func (i *rpmInfo) NEVRA() string { return i.Name + "-" + i.EVR() + "." + i.Arch }

type indexEntry struct {
	typ    uint32
	offset uint32
	count  uint32
}

type header struct {
	entries map[uint32]indexEntry
	store   []byte
}

const (
	maxIndexEntries = 1 << 16
	maxStore        = 256 << 20
)

// readHeader reads a header structure at off and returns it with the
// offset just past its end.
func readHeader(r io.ReaderAt, off int64) (*header, int64, error) {
	pre := make([]byte, 16)
	if _, err := r.ReadAt(pre, off); err != nil {
		return nil, 0, fmt.Errorf("read header: %w", err)
	}
	if !bytes.Equal(pre[:3], []byte{0x8e, 0xad, 0xe8}) {
		return nil, 0, errors.New("bad header magic")
	}
	n := binary.BigEndian.Uint32(pre[8:12])
	size := binary.BigEndian.Uint32(pre[12:16])
	if n > maxIndexEntries || size > maxStore {
		return nil, 0, errors.New("header too large")
	}
	idx := make([]byte, 16*int(n))
	if _, err := r.ReadAt(idx, off+16); err != nil {
		return nil, 0, fmt.Errorf("read header index: %w", err)
	}
	h := &header{entries: make(map[uint32]indexEntry, n), store: make([]byte, size)}
	if _, err := r.ReadAt(h.store, off+16+int64(len(idx))); err != nil {
		return nil, 0, fmt.Errorf("read header store: %w", err)
	}
	for i := 0; i < int(n); i++ {
		e := idx[16*i:]
		tag := binary.BigEndian.Uint32(e[0:4])
		ie := indexEntry{typ: binary.BigEndian.Uint32(e[4:8]), offset: binary.BigEndian.Uint32(e[8:12]), count: binary.BigEndian.Uint32(e[12:16])}
		if ie.offset > size {
			return nil, 0, errors.New("header entry out of range")
		}
		h.entries[tag] = ie
	}
	return h, off + 16 + int64(len(idx)) + int64(size), nil
}

func (h *header) strings(tag uint32) []string {
	e, ok := h.entries[tag]
	if !ok {
		return nil
	}
	switch e.typ {
	case typeString, typeI18NString, typeStringArray:
	default:
		return nil
	}
	count := int(e.count)
	if e.typ == typeString {
		count = 1
	}
	if count > len(h.store) {
		return nil
	}
	out := make([]string, 0, count)
	b := h.store[e.offset:]
	for i := 0; i < count; i++ {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			break
		}
		out = append(out, string(b[:j]))
		b = b[j+1:]
		if e.typ == typeI18NString {
			break // first (default) translation only
		}
	}
	return out
}

func (h *header) string(tag uint32) string {
	if s := h.strings(tag); len(s) > 0 {
		return s[0]
	}
	return ""
}

func (h *header) ints(tag uint32) []int64 {
	e, ok := h.entries[tag]
	if !ok {
		return nil
	}
	var width int
	switch e.typ {
	case typeChar, typeInt8:
		width = 1
	case typeInt16:
		width = 2
	case typeInt32:
		width = 4
	case typeInt64:
		width = 8
	default:
		return nil
	}
	end := int(e.offset) + width*int(e.count)
	if end > len(h.store) || end < int(e.offset) {
		return nil
	}
	out := make([]int64, e.count)
	b := h.store[e.offset:end]
	for i := range out {
		switch width {
		case 1:
			out[i] = int64(b[i])
		case 2:
			out[i] = int64(binary.BigEndian.Uint16(b[2*i:]))
		case 4:
			out[i] = int64(binary.BigEndian.Uint32(b[4*i:]))
		case 8:
			out[i] = int64(binary.BigEndian.Uint64(b[8*i:]))
		}
	}
	return out
}

func (h *header) int(tag uint32) (int64, bool) {
	if v := h.ints(tag); len(v) > 0 {
		return v[0], true
	}
	return 0, false
}

// parseRPM reads the lead, signature header and header of an RPM.
func parseRPM(r io.ReaderAt, size int64) (*rpmInfo, error) {
	lead := make([]byte, 96)
	if _, err := r.ReadAt(lead, 0); err != nil || !bytes.Equal(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, errors.New("not an RPM package (bad lead)")
	}
	sig, sigEnd, err := readHeader(r, 96)
	if err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	start := (sigEnd + 7) &^ 7
	h, end, err := readHeader(r, start)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if end > size {
		return nil, errors.New("truncated RPM")
	}
	info := &rpmInfo{
		Name: h.string(tagName), Version: h.string(tagVersion), Release: h.string(tagRelease), Arch: h.string(tagArch),
		Summary: h.string(tagSummary), Description: h.string(tagDescription), Packager: h.string(tagPackager),
		URL: h.string(tagURL), License: h.string(tagLicense), Vendor: h.string(tagVendor), Group: h.string(tagGroup),
		BuildHost: h.string(tagBuildHost), SourceRPM: h.string(tagSourceRPM),
		HeaderStart: start, HeaderEnd: end, Epoch: "0",
	}
	if e, ok := h.int(tagEpoch); ok {
		info.Epoch = strconv.FormatInt(e, 10)
	}
	if _, isSrc := h.entries[tagSourcePackage]; isSrc || info.SourceRPM == "" {
		info.Arch = "src"
		info.SourceRPM = ""
	}
	switch {
	case !rpmNameRe.MatchString(info.Name):
		return nil, fmt.Errorf("invalid or missing name %q", info.Name)
	case !rpmVerRe.MatchString(info.Version), !rpmVerRe.MatchString(info.Release):
		return nil, fmt.Errorf("invalid version %q-%q", info.Version, info.Release)
	case !rpmArchRe.MatchString(info.Arch):
		return nil, fmt.Errorf("invalid arch %q", info.Arch)
	}
	info.BuildTime, _ = h.int(tagBuildTime)
	if v, ok := h.int(tagLongSize); ok {
		info.InstalledSize = v
	} else {
		info.InstalledSize, _ = h.int(tagSize)
	}
	if v, ok := sig.int(sigTagLongArchiveSize); ok {
		info.ArchiveSize = v
	} else if v, ok := sig.int(sigTagPayloadSize); ok {
		info.ArchiveSize = v
	} else {
		info.ArchiveSize, _ = h.int(tagArchiveSize)
	}

	info.Provides = deps(h, tagProvideName, tagProvideFlags, tagProvideVer, false)
	info.Requires = deps(h, tagRequireName, tagRequireFlags, tagRequireVer, true)
	info.Conflicts = deps(h, tagConflictName, tagConflictFlags, tagConflictVer, false)
	info.Obsoletes = deps(h, tagObsoleteName, tagObsoleteFlags, tagObsoleteVer, false)
	info.Recommends = deps(h, tagRecommendName, tagRecommendFlg, tagRecommendVer, false)
	info.Suggests = deps(h, tagSuggestName, tagSuggestFlg, tagSuggestVer, false)
	info.Supplements = deps(h, tagSupplementNam, tagSupplementFlg, tagSupplementVer, false)
	info.Enhances = deps(h, tagEnhanceName, tagEnhanceFlg, tagEnhanceVer, false)
	info.Files = files(h)
	info.Requires = dropSelfProvided(info.Requires, info.Provides, info.Files)
	info.Changelogs = changelogs(h, changelogLimit)
	return info, nil
}

func flagString(f int64) string {
	switch f & (senseLess | senseGreater | senseEqual) {
	case senseEqual:
		return "EQ"
	case senseLess:
		return "LT"
	case senseGreater:
		return "GT"
	case senseLess | senseEqual:
		return "LE"
	case senseGreater | senseEqual:
		return "GE"
	}
	return ""
}

// splitEVR splits [epoch:]version[-release].
func splitEVR(s string) (epoch, ver, rel string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if _, err := strconv.Atoi(s[:i]); err == nil {
			epoch, s = s[:i], s[i+1:]
		}
	}
	ver = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		ver, rel = s[:i], s[i+1:]
	}
	if epoch == "" {
		epoch = "0"
	}
	return epoch, ver, rel
}

func deps(h *header, nameTag, flagTag, verTag uint32, requires bool) []rpmDep {
	names := h.strings(nameTag)
	flags := h.ints(flagTag)
	vers := h.strings(verTag)
	var out []rpmDep
	seen := map[rpmDep]bool{}
	for i, n := range names {
		var f int64
		if i < len(flags) {
			f = flags[i]
		}
		if requires && (strings.HasPrefix(n, "rpmlib(") || f&senseRPMLib != 0) {
			continue
		}
		d := rpmDep{Name: n, Flags: flagString(f)}
		if i < len(vers) && vers[i] != "" {
			d.Epoch, d.Ver, d.Rel = splitEVR(vers[i])
		}
		if requires && f&(sensePreReq|senseScriptPre|senseScriptPost) != 0 {
			d.Pre = true
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// dropSelfProvided removes requirements the package satisfies itself, as
// createrepo_c does: requires identical to one of its provides, and file
// requires on its own primary files.
func dropSelfProvided(reqs, provs []rpmDep, fs []rpmFile) []rpmDep {
	own := map[string]bool{}
	for _, f := range fs {
		own[f.Path] = true
	}
	out := reqs[:0]
	for _, r := range reqs {
		if strings.HasPrefix(r.Name, "/") && own[r.Name] && isPrimaryFile(r.Name) {
			continue
		}
		self := false
		for _, p := range provs {
			if p.Name == r.Name && p.Flags == r.Flags && p.Epoch == r.Epoch && p.Ver == r.Ver && p.Rel == r.Rel {
				self = true
				break
			}
		}
		if !self {
			out = append(out, r)
		}
	}
	return out
}

func files(h *header) []rpmFile {
	var paths []string
	if base := h.strings(tagBaseNames); len(base) > 0 {
		dirs := h.strings(tagDirNames)
		idx := h.ints(tagDirIndexes)
		for i, b := range base {
			if i >= len(idx) || int(idx[i]) >= len(dirs) {
				break
			}
			paths = append(paths, dirs[idx[i]]+b)
		}
	} else {
		paths = h.strings(tagOldFilenames)
	}
	modes := h.ints(tagFileModes)
	fflags := h.ints(tagFileFlags)
	out := make([]rpmFile, 0, len(paths))
	for i, p := range paths {
		f := rpmFile{Path: p}
		switch {
		case i < len(fflags) && fflags[i]&fileGhost != 0:
			f.Type = "ghost"
		case i < len(modes) && modes[i]&0o170000 == 0o040000:
			f.Type = "dir"
		}
		out = append(out, f)
	}
	return out
}

// changelogLimit matches createrepo_c's default --changelog-limit.
const changelogLimit = 10

func changelogs(h *header, limit int) []rpmChangelog {
	times := h.ints(tagChangelogTime)
	names := h.strings(tagChangelogName)
	texts := h.strings(tagChangelogText)
	n := min(len(times), len(names), len(texts), limit)
	out := make([]rpmChangelog, 0, n)
	// The header lists the newest entry first; repodata lists oldest first.
	for i := n - 1; i >= 0; i-- {
		out = append(out, rpmChangelog{Author: names[i], Date: times[i], Text: texts[i]})
	}
	return out
}
