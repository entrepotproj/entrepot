package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Trivy runs the trivy CLI.
type Trivy struct {
	Binary      string
	ServerURL   string
	ServerToken string
	ExtraArgs   []string
	// WorkDir is the working directory of the process.
	WorkDir string
}

func (t *Trivy) bin() string {
	if t.Binary == "" {
		return "trivy"
	}
	return t.Binary
}

// env passes the server token through the environment (TRIVY_TOKEN) so it
// does not show up in process listings.
func (t *Trivy) env() []string {
	if t.ServerToken == "" {
		return nil
	}
	return append(os.Environ(), "TRIVY_TOKEN="+t.ServerToken)
}

// Args returns the trivy command line for a target.
//
//	package: trivy sbom --format json --quiet [--server URL] [extra...] SBOM.json
//	image:   trivy image --input LAYOUT_DIR --format json --quiet [--server URL] [extra...]
func (t *Trivy) Args(tg Target) []string {
	var args []string
	switch tg.Kind {
	case KindImage:
		args = []string{"image", "--input", tg.LayoutDir, "--format", "json", "--quiet", "--scanners", "vuln"}
	default:
		args = []string{"sbom", "--format", "json", "--quiet", "--scanners", "vuln"}
	}
	if t.ServerURL != "" {
		args = append(args, "--server", t.ServerURL)
	}
	args = append(args, t.ExtraArgs...)
	if tg.Kind != KindImage {
		args = append(args, tg.SBOMPath)
	}
	return args
}

func (t *Trivy) Scan(ctx context.Context, tg Target) (*Outcome, error) {
	out, err := runCLI(ctx, t.WorkDir, t.env(), t.bin(), t.Args(tg)...)
	if err != nil {
		return nil, err
	}
	o, err := ParseTrivy(out)
	if err != nil {
		return nil, err
	}
	if o.ScannerVersion == "" || o.DBVersion == "" {
		if v, db, err := t.Version(ctx); err == nil {
			if o.ScannerVersion == "" {
				o.ScannerVersion = v
			}
			o.DBVersion = db
		}
	}
	return o, nil
}

// cacheArgs returns the --cache-dir option of ExtraArgs (the version
// command reports the vulnerability DB found there).
func (t *Trivy) cacheArgs() []string {
	for i, a := range t.ExtraArgs {
		if a == "--cache-dir" && i+1 < len(t.ExtraArgs) {
			return []string{a, t.ExtraArgs[i+1]}
		}
		if strings.HasPrefix(a, "--cache-dir=") {
			return []string{a}
		}
	}
	return nil
}

func (t *Trivy) Version(ctx context.Context) (string, string, error) {
	out, err := runCLI(ctx, t.WorkDir, t.env(), t.bin(), append([]string{"--version", "--format", "json"}, t.cacheArgs()...)...)
	if err == nil {
		var v struct {
			Version         string `json:"Version"`
			VulnerabilityDB *struct {
				Version   int    `json:"Version"`
				UpdatedAt string `json:"UpdatedAt"`
			} `json:"VulnerabilityDB"`
		}
		if json.Unmarshal(out, &v) == nil && v.Version != "" {
			db := ""
			if v.VulnerabilityDB != nil {
				db = fmt.Sprintf("v%d", v.VulnerabilityDB.Version)
				if v.VulnerabilityDB.UpdatedAt != "" {
					db += " " + v.VulnerabilityDB.UpdatedAt
				}
			}
			return v.Version, db, nil
		}
	}
	out, err2 := runCLI(ctx, t.WorkDir, t.env(), t.bin(), "--version")
	if err2 != nil {
		if err != nil {
			return "", "", err
		}
		return "", "", err2
	}
	v := versionLine(string(out))
	if v == "" {
		v = strings.TrimSpace(firstLine(string(out)))
	}
	return v, "", nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// ParseTrivy parses `trivy --format json` output.
func ParseTrivy(b []byte) (*Outcome, error) {
	var rep struct {
		Trivy *struct {
			Version string `json:"Version"`
		} `json:"Trivy"`
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				Description      string `json:"Description"`
				PrimaryURL       string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy report: %w", err)
	}
	o := &Outcome{Status: StatusOK}
	if rep.Trivy != nil {
		o.ScannerVersion = rep.Trivy.Version
	}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			title := v.Title
			if title == "" {
				title = firstLine(v.Description)
			}
			o.Findings = append(o.Findings, Finding{
				VulnID: v.VulnerabilityID, Severity: v.Severity, Package: v.PkgName,
				InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, Title: title, URL: v.PrimaryURL,
			})
		}
	}
	o.Findings = Dedupe(o.Findings)
	return o, nil
}
