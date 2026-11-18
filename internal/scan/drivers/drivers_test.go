package drivers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].VulnID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestPURL(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Type: "npm", Name: "lodash", Version: "4.17.20"}, "pkg:npm/lodash@4.17.20"},
		{Package{Type: "npm", Namespace: "@babel", Name: "traverse", Version: "7.23.0"}, "pkg:npm/%40babel/traverse@7.23.0"},
		{Package{Type: "pypi", Name: "django", Version: "3.2.0"}, "pkg:pypi/django@3.2.0"},
		{Package{Type: "deb", Namespace: "debian", Name: "tar", Version: "1.34+dfsg-1.2",
			Qualifiers: map[string]string{"arch": "amd64", "distro": "debian-12"}},
			"pkg:deb/debian/tar@1.34%2Bdfsg-1.2?arch=amd64&distro=debian-12"},
		{Package{Type: "rpm", Namespace: "rocky", Name: "openssl", Version: "3.0.7-24.el9",
			Qualifiers: map[string]string{"arch": "x86_64", "epoch": "1", "distro": ""}},
			"pkg:rpm/rocky/openssl@3.0.7-24.el9?arch=x86_64&epoch=1"},
	}
	for _, c := range cases {
		if got := c.p.PURL(); got != c.want {
			t.Errorf("PURL() = %s, want %s", got, c.want)
		}
	}
	if n, v, ok := purlNameVersion("pkg:npm/%40babel/traverse@7.23.0?x=1"); !ok || n != "@babel/traverse" || v != "7.23.0" {
		t.Errorf("purlNameVersion = %q %q %v", n, v, ok)
	}
}

func TestSBOM(t *testing.T) {
	b, err := SBOM(Package{Type: "deb", Namespace: "debian", Name: "openssl", Version: "3.0.11-1~deb12u1",
		Qualifiers: map[string]string{"arch": "amd64", "distro": "debian-12"}}, "debian-12")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Type, Name, Version, PURL string
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || len(doc.Components) != 2 {
		t.Fatalf("unexpected SBOM: %s", b)
	}
	if doc.Components[0].Type != "operating-system" || doc.Components[0].Name != "debian" || doc.Components[0].Version != "12" {
		t.Errorf("os component = %+v", doc.Components[0])
	}
	if !strings.Contains(string(b), `"purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12"`) {
		t.Errorf("purl missing: %s", b)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": "critical", "High": "high", "moderate": "medium", "Negligible": "low", "UNKNOWN": "unknown",
		"": "unknown", "9.8": "critical", "7.2": "high", "5": "medium", "0.1": "low", "bogus": "unknown",
	} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

// Output captured from trivy (built from source) scanning lodash@4.17.20.
func TestParseTrivy(t *testing.T) {
	o, err := ParseTrivy(fixture(t, "trivy-lodash.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Findings) != 4 || o.Status != StatusOK {
		t.Fatalf("findings = %+v", o.Findings)
	}
	f := find(o.Findings, "CVE-2021-23337")
	if f == nil || f.Severity != "high" || f.Package != "lodash" || f.InstalledVersion != "4.17.20" ||
		f.FixedVersion != "4.17.21" || !strings.Contains(f.Title, "command injection") ||
		f.URL != "https://avd.aquasec.com/nvd/cve-2021-23337" {
		t.Errorf("CVE-2021-23337 = %+v", f)
	}
	// Sorted by severity.
	if o.Findings[0].Severity != "high" || o.Findings[3].Severity != "medium" {
		t.Errorf("not sorted: %+v", o.Findings)
	}
	// Image report: duplicate vuln on two packages is kept per package.
	o, err = ParseTrivy(fixture(t, "trivy-image.json"))
	if err != nil || len(o.Findings) != 3 || o.ScannerVersion != "0.99.0-fake" {
		t.Fatalf("image: %v %+v", err, o)
	}
}

func TestParseGrype(t *testing.T) {
	o, err := ParseGrype(fixture(t, "grype-lodash.json"))
	if err != nil {
		t.Fatal(err)
	}
	if o.ScannerVersion != "0.86.1" || o.DBVersion != "v6.0.2 2024-12-10T01:30:28Z" {
		t.Errorf("versions = %q %q", o.ScannerVersion, o.DBVersion)
	}
	if len(o.Findings) != 3 {
		t.Fatalf("findings = %+v", o.Findings)
	}
	f := find(o.Findings, "GHSA-35jh-r3h4-6jhm")
	if f == nil || f.Severity != "high" || f.FixedVersion != "4.17.21" || f.Package != "lodash" ||
		f.URL != "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" || f.Title != "Command Injection in lodash" {
		t.Errorf("GHSA = %+v", f)
	}
	if f := find(o.Findings, "CVE-2005-2541"); f == nil || f.Severity != "low" {
		t.Errorf("negligible = %+v", f)
	}
}

// SARIF produced by `trivy sbom --format sarif`.
func TestParseSARIFTrivy(t *testing.T) {
	fs, err := ParseSARIF(fixture(t, "trivy-lodash.sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("findings = %+v", fs)
	}
	f := find(fs, "CVE-2021-23337")
	if f == nil || f.Severity != "high" || f.Package != "lodash" || f.InstalledVersion != "4.17.20" || f.FixedVersion != "4.17.21" ||
		f.URL != "https://avd.aquasec.com/nvd/cve-2021-23337" || f.Title != "nodejs-lodash: command injection via template" {
		t.Errorf("CVE-2021-23337 = %+v", f)
	}
}

// Grype/CodeQL style SARIF: severity only in rule properties, package in
// the location message.
func TestParseSARIFRules(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype","rules":[
		{"id":"CVE-2022-0001-pkg","shortDescription":{"text":"CVE-2022-0001 pkg 1.0"},"helpUri":"https://example/cve",
		 "properties":{"security-severity":"9.8"}},
		{"id":"R2","properties":{"tags":["security","low"]}}]}},
	  "results":[
		{"ruleId":"CVE-2022-0001-pkg","level":"error","message":{"text":"A vulnerability"},
		 "locations":[{"message":{"text":"pkg@1.0"}}]},
		{"ruleIndex":1,"level":"note","message":{"text":"something"}},
		{"ruleId":"R3","level":"warning","message":{"text":"no rule"}}]}]}`
	fs, err := ParseSARIF([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %+v", fs)
	}
	if f := find(fs, "CVE-2022-0001-pkg"); f.Severity != "critical" || f.Package != "pkg" || f.InstalledVersion != "1.0" ||
		f.URL != "https://example/cve" {
		t.Errorf("rule severity: %+v", f)
	}
	if f := find(fs, "R2"); f == nil || f.Severity != "low" {
		t.Errorf("tag severity: %+v", f)
	}
	if f := find(fs, "R3"); f == nil || f.Severity != "medium" {
		t.Errorf("level severity: %+v", f)
	}
	if _, err := ParseSARIF([]byte(`{"foo":1}`)); err == nil {
		t.Error("expected error for a document without runs")
	}
}

// CycloneDX produced by `trivy sbom --format cyclonedx`.
func TestParseCycloneDX(t *testing.T) {
	fs, err := ParseCycloneDX(fixture(t, "trivy-lodash.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("findings = %+v", fs)
	}
	f := find(fs, "CVE-2021-23337")
	if f == nil || f.Severity != "high" || f.Package != "lodash" || f.InstalledVersion != "4.17.20" || f.FixedVersion != "4.17.21" ||
		!strings.HasPrefix(f.URL, "https://") {
		t.Errorf("CVE-2021-23337 = %+v", f)
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"bom-ref":"c1","group":"@scope","name":"x","version":"1"}],
	  "vulnerabilities":[
	    {"id":"CVE-1","ratings":[{"score":9.1}],"affects":[{"ref":"c1"}]},
	    {"id":"CVE-2","ratings":[{"severity":"high"}],"affects":[{"ref":"c1"}],"analysis":{"state":"not_affected"}},
	    {"id":"CVE-3","ratings":[{"severity":"info"}],"affects":[{"ref":"pkg:pypi/requests@2.0","versions":[{"version":"2.0.1","status":"unaffected"}]}]}]}`
	fs, err = ParseCycloneDX([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %+v", fs)
	}
	if f := find(fs, "CVE-1"); f.Severity != "critical" || f.Package != "@scope/x" || f.InstalledVersion != "1" {
		t.Errorf("CVE-1 = %+v", f)
	}
	if f := find(fs, "CVE-3"); f.Severity != "low" || f.Package != "requests" || f.InstalledVersion != "2.0" || f.FixedVersion != "2.0.1" {
		t.Errorf("CVE-3 = %+v", f)
	}
}

func TestCLIArgsAndFakeBinaries(t *testing.T) {
	tr := &Trivy{ServerURL: "http://trivy:4954", ExtraArgs: []string{"--offline-scan"}}
	got := strings.Join(tr.Args(Target{Kind: KindPackage, SBOMPath: "/w/sbom.json"}), " ")
	if got != "sbom --format json --quiet --scanners vuln --server http://trivy:4954 --offline-scan /w/sbom.json" {
		t.Errorf("trivy sbom args: %s", got)
	}
	got = strings.Join(tr.Args(Target{Kind: KindImage, LayoutDir: "/w/img"}), " ")
	if got != "image --input /w/img --format json --quiet --scanners vuln --server http://trivy:4954 --offline-scan" {
		t.Errorf("trivy image args: %s", got)
	}
	gr := &Grype{}
	if got := strings.Join(gr.Args(Target{Kind: KindPackage, SBOMPath: "/s.json", Distro: "debian-12"}), " "); got != "sbom:/s.json -o json --distro debian:12" {
		t.Errorf("grype args: %s", got)
	}
	if got := strings.Join(gr.Args(Target{Kind: KindImage, LayoutDir: "/l"}), " "); got != "oci-dir:/l -o json" {
		t.Errorf("grype image args: %s", got)
	}

	bin, _ := filepath.Abs(filepath.Join("..", "testdata", "fake-trivy.sh"))
	dir := t.TempDir()
	tr = &Trivy{Binary: bin, WorkDir: dir}
	v, db, err := tr.Version(context.Background())
	if err != nil || v != "0.99.0-fake" || !strings.HasPrefix(db, "v2") {
		t.Fatalf("version: %q %q %v", v, db, err)
	}
	sbom := filepath.Join(dir, "sbom.json")
	if err := WriteSBOM(sbom, Package{Type: "npm", Name: "lodash", Version: "4.17.20"}, ""); err != nil {
		t.Fatal(err)
	}
	o, err := tr.Scan(context.Background(), Target{Kind: KindPackage, SBOMPath: sbom})
	if err != nil || len(o.Findings) != 4 || o.DBVersion == "" {
		t.Fatalf("scan: %v %+v", err, o)
	}
	// Errors carry stderr.
	_, err = tr.Scan(context.Background(), Target{Kind: KindImage, LayoutDir: dir})
	if err == nil || !strings.Contains(err.Error(), "not an OCI layout") {
		t.Fatalf("expected layout error, got %v", err)
	}
	gbin, _ := filepath.Abs(filepath.Join("..", "testdata", "fake-grype.sh"))
	g := &Grype{Binary: gbin, WorkDir: dir}
	if v, _, err := g.Version(context.Background()); err != nil || v != "0.86.1" {
		t.Fatalf("grype version %q %v", v, err)
	}
	o, err = g.Scan(context.Background(), Target{Kind: KindPackage, SBOMPath: sbom})
	if err != nil || len(o.Findings) != 3 {
		t.Fatalf("grype scan: %v %+v", err, o)
	}
}
