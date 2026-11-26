// Package drivers runs vulnerability scanners (Trivy and Grype CLIs) and
// parses scanner output formats (Trivy JSON, Grype JSON, SARIF 2.1 and
// CycloneDX vulnerabilities) into normalised findings.
package drivers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Target kinds.
const (
	KindPackage = "package"
	KindImage   = "image"
	// KindFiles targets are the files of a component (Files), for scanners
	// that read content (MetaDefender).
	KindFiles = "files"
)

// Outcome statuses.
const (
	StatusOK          = "ok"
	StatusUnsupported = "unsupported"
)

// Target is what a driver scans.
type Target struct {
	// Kind is KindPackage (SBOMPath is a CycloneDX SBOM with one package) or
	// KindImage (LayoutDirs are OCI image layouts, one per platform).
	Kind string
	// PURL of a package target.
	PURL string
	// Distro (e.g. debian-12) qualifies OS packages.
	Distro string
	// SBOMPath is the CycloneDX file of a package target.
	SBOMPath string
	// LayoutDir is the OCI image layout directory of an image target.
	LayoutDir string
	// Description is shown in results (purl or image reference).
	Description string
	// Files of a KindFiles target.
	Files []File
}

// File is one file of a KindFiles target. Open is called only when the
// content is needed (a scanner may already know the file by its hash).
type File struct {
	// Name is the file name sent to the scanner.
	Name string
	// Label names the file in findings (defaults to Name), e.g. a Docker
	// layer and its platforms.
	Label string
	Size  int64
	// SHA256 of the content, hex.
	SHA256    string
	MediaType string
	Open      func(ctx context.Context) (io.ReadCloser, error)
}

// FileResult records how a file of a KindFiles target was scanned.
type FileResult struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256,omitempty"`
	// DataID identifies the analysis in the scanner.
	DataID string `json:"dataId,omitempty"`
	Result string `json:"result,omitempty"`
	// Cached is true when an earlier analysis of the same content was used.
	Cached bool `json:"cached,omitempty"`
}

// Threat finding id prefixes (malware scanners report threats, not CVEs).
// Waivers for "*" don't cover them.
const (
	ThreatMalware    = "MALWARE:"
	ThreatSuspicious = "SUSPICIOUS:"
	ThreatPUA        = "PUA:"
	ThreatBlocked    = "BLOCKED:"
)

// IsThreat reports whether a finding id is a threat rather than a
// vulnerability.
func IsThreat(vulnID string) bool {
	return FindingKind(vulnID) != "vulnerability"
}

// FindingKind is vulnerability, malware (MALWARE:, SUSPICIOUS:, PUA:) or
// policy (BLOCKED:, the scanner's policy refused the file).
func FindingKind(vulnID string) string {
	switch {
	case strings.HasPrefix(vulnID, ThreatMalware), strings.HasPrefix(vulnID, ThreatSuspicious), strings.HasPrefix(vulnID, ThreatPUA):
		return "malware"
	case strings.HasPrefix(vulnID, ThreatBlocked):
		return "policy"
	}
	return "vulnerability"
}

// Finding is one vulnerability.
type Finding struct {
	VulnID           string `json:"vulnId"`
	Severity         string `json:"severity"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	Title            string `json:"title"`
	URL              string `json:"url"`
}

// Outcome is the result of a scan.
type Outcome struct {
	Status         string
	Findings       []Finding
	ScannerVersion string
	DBVersion      string
	// Files of a KindFiles target.
	Files []FileResult
}

// Driver scans targets with one scanner.
type Driver interface {
	Scan(ctx context.Context, t Target) (*Outcome, error)
	// Version reports the scanner (and database) version.
	Version(ctx context.Context) (version, db string, err error)
}

// Severities in decreasing order.
var Severities = []string{"critical", "high", "medium", "low", "unknown"}

// NormalizeSeverity maps scanner severities to critical|high|medium|low|unknown.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high", "important", "error":
		return "high"
	case "medium", "moderate", "warning", "warn":
		return "medium"
	case "low", "negligible", "minor", "note", "info", "informational":
		return "low"
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return SeverityFromScore(f)
	}
	return "unknown"
}

// SeverityFromScore maps a CVSS base score to a severity.
func SeverityFromScore(f float64) string {
	switch {
	case f >= 9:
		return "critical"
	case f >= 7:
		return "high"
	case f >= 4:
		return "medium"
	case f > 0:
		return "low"
	}
	return "unknown"
}

// SeverityRank orders severities: critical=4 ... low=1, unknown=0.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Dedupe removes duplicate findings (same vulnerability, package and
// version) and sorts by severity, then id.
func Dedupe(fs []Finding) []Finding {
	seen := map[string]int{}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		f.Severity = NormalizeSeverity(f.Severity)
		if f.VulnID == "" {
			continue
		}
		f.Title = truncate(f.Title, 500)
		k := f.VulnID + "\x00" + f.Package + "\x00" + f.InstalledVersion
		if i, ok := seen[k]; ok {
			if SeverityRank(f.Severity) > SeverityRank(out[i].Severity) {
				out[i].Severity = f.Severity
			}
			if out[i].FixedVersion == "" {
				out[i].FixedVersion = f.FixedVersion
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := SeverityRank(out[i].Severity), SeverityRank(out[j].Severity); a != b {
			return a > b
		}
		if out[i].VulnID != out[j].VulnID {
			return out[i].VulnID < out[j].VulnID
		}
		return out[i].Package < out[j].Package
	})
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// maxOutput bounds scanner stdout (JSON reports of large images).
const maxOutput = 512 << 20

// runCLI runs a scanner command and returns its stdout. Errors include the
// tail of stderr.
func runCLI(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.WaitDelay = 5 * time.Second
	var stdout limitedBuffer
	stdout.max = maxOutput
	var stderr tailBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	if stdout.overflow {
		return nil, fmt.Errorf("%s: output exceeds %d bytes", name, maxOutput)
	}
	if err != nil {
		var ee *exec.ExitError
		msg := strings.TrimSpace(stderr.String())
		if errors.As(err, &ee) {
			if msg == "" {
				msg = strings.TrimSpace(truncate(stdout.String(), 2000))
			}
			return stdout.Bytes(), fmt.Errorf("%s exited with status %d: %s", name, ee.ExitCode(), msg)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// tailBuffer keeps the last 4 KiB written.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }

var _ io.Writer = (*tailBuffer)(nil)

// versionLine extracts "Version: x" from plain-text version output.
func versionLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "version") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
