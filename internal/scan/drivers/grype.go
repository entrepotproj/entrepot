package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Grype runs the grype CLI.
type Grype struct {
	Binary    string
	ExtraArgs []string
	WorkDir   string
}

func (g *Grype) bin() string {
	if g.Binary == "" {
		return "grype"
	}
	return g.Binary
}

// Args returns the grype command line for a target.
//
//	package: grype sbom:SBOM.json -o json [--distro name:version] [extra...]
//	image:   grype oci-dir:LAYOUT_DIR -o json [extra...]
func (g *Grype) Args(tg Target) []string {
	var args []string
	switch tg.Kind {
	case KindImage:
		args = []string{"oci-dir:" + tg.LayoutDir, "-o", "json"}
	default:
		args = []string{"sbom:" + tg.SBOMPath, "-o", "json"}
		if name, version := OSRelease(tg.Distro); name != "" && version != "" {
			if name == "redhat" {
				name = "rhel"
			}
			args = append(args, "--distro", name+":"+version)
		}
	}
	return append(args, g.ExtraArgs...)
}

func (g *Grype) Scan(ctx context.Context, tg Target) (*Outcome, error) {
	out, err := runCLI(ctx, g.WorkDir, nil, g.bin(), g.Args(tg)...)
	if err != nil {
		return nil, err
	}
	return ParseGrype(out)
}

func (g *Grype) Version(ctx context.Context) (string, string, error) {
	out, err := runCLI(ctx, g.WorkDir, nil, g.bin(), "version")
	if err != nil {
		return "", "", err
	}
	v := versionLine(string(out))
	if v == "" {
		v = strings.TrimSpace(firstLine(string(out)))
	}
	return v, "", nil
}

// ParseGrype parses `grype -o json` output.
func ParseGrype(b []byte) (*Outcome, error) {
	var rep struct {
		Matches []struct {
			Vulnerability struct {
				ID          string   `json:"id"`
				DataSource  string   `json:"dataSource"`
				Severity    string   `json:"severity"`
				URLs        []string `json:"urls"`
				Description string   `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			RelatedVulnerabilities []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
		Descriptor struct {
			Name    string          `json:"name"`
			Version string          `json:"version"`
			DB      json.RawMessage `json:"db"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse grype report: %w", err)
	}
	o := &Outcome{Status: StatusOK, ScannerVersion: rep.Descriptor.Version, DBVersion: grypeDB(rep.Descriptor.DB)}
	for _, m := range rep.Matches {
		v := m.Vulnerability
		url := v.DataSource
		if url == "" && len(v.URLs) > 0 {
			url = v.URLs[0]
		}
		title := firstLine(v.Description)
		if title == "" {
			for _, rv := range m.RelatedVulnerabilities {
				if rv.Description != "" {
					title = firstLine(rv.Description)
					break
				}
			}
		}
		o.Findings = append(o.Findings, Finding{
			VulnID: v.ID, Severity: v.Severity, Package: m.Artifact.Name, InstalledVersion: m.Artifact.Version,
			FixedVersion: strings.Join(v.Fix.Versions, ", "), Title: title, URL: url,
		})
	}
	o.Findings = Dedupe(o.Findings)
	return o, nil
}

// grypeDB summarises descriptor.db (its shape differs between versions).
func grypeDB(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if st, ok := m["status"].(map[string]any); ok {
		m = st
	}
	var parts []string
	for _, k := range []string{"schemaVersion", "built"} {
		switch v := m[k].(type) {
		case string:
			parts = append(parts, v)
		case float64:
			parts = append(parts, fmt.Sprintf("v%d", int(v)))
		}
	}
	return strings.Join(parts, " ")
}
