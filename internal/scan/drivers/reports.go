package drivers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseSARIF extracts vulnerability findings from a SARIF 2.1 log: each
// runs[].results[] is a finding identified by ruleId. Severity comes from
// properties["security-severity"] (CVSS score) of the result or its rule,
// a "Severity: X" line in the message (Trivy), the rule's tags, or the
// result level (error=high, warning=medium, note=low).
func ParseSARIF(b []byte) ([]Finding, error) {
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []sarifRule `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string         `json:"ruleId"`
				RuleIndex *int           `json:"ruleIndex"`
				Level     string         `json:"level"`
				Message   sarifText      `json:"message"`
				Props     map[string]any `json:"properties"`
				Locations []struct {
					Message sarifText `json:"message"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		return nil, fmt.Errorf("invalid SARIF document: %w", err)
	}
	if log.Runs == nil {
		return nil, fmt.Errorf("invalid SARIF document: no runs")
	}
	var out []Finding
	for _, run := range log.Runs {
		rules := map[string]*sarifRule{}
		for i := range run.Tool.Driver.Rules {
			rules[run.Tool.Driver.Rules[i].ID] = &run.Tool.Driver.Rules[i]
		}
		for _, res := range run.Results {
			rule := rules[res.RuleID]
			if rule == nil && res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = &run.Tool.Driver.Rules[*res.RuleIndex]
			}
			if res.RuleID == "" && rule != nil {
				res.RuleID = rule.ID
			}
			fields := keyValues(res.Message.Text)
			f := Finding{VulnID: res.RuleID, Package: fields["package"], InstalledVersion: fields["installed version"],
				FixedVersion: fields["fixed version"]}
			if f.Package == "" {
				for _, l := range res.Locations {
					// "Node.js: lodash@4.17.20" / "lodash@4.17.20"
					m := l.Message.Text
					if i := strings.LastIndex(m, ": "); i >= 0 {
						m = m[i+2:]
					}
					if at := strings.LastIndex(m, "@"); at > 0 {
						f.Package, f.InstalledVersion = m[:at], m[at+1:]
						break
					}
				}
			}
			f.Severity = sarifSeverity(res.Props, rule, fields["severity"], res.Level)
			if rule != nil {
				f.Title = rule.ShortDescription.Text
				if f.Title == "" {
					f.Title = firstLine(rule.FullDescription.Text)
				}
				f.URL = rule.HelpURI
			}
			if f.Title == "" {
				f.Title = firstLine(res.Message.Text)
			}
			if f.URL == "" {
				f.URL = firstURL(res.Message.Text)
			}
			out = append(out, f)
		}
	}
	return Dedupe(out), nil
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	FullDescription  sarifText `json:"fullDescription"`
	HelpURI          string    `json:"helpUri"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Props map[string]any `json:"properties"`
}

func sarifSeverity(props map[string]any, rule *sarifRule, msgSeverity, level string) string {
	if s := securitySeverity(props); s != "" {
		return s
	}
	if msgSeverity != "" {
		if s := NormalizeSeverity(msgSeverity); s != "unknown" {
			return s
		}
	}
	if rule != nil {
		if s := securitySeverity(rule.Props); s != "" {
			return s
		}
		if tags, ok := rule.Props["tags"].([]any); ok {
			for _, t := range tags {
				if ts, ok := t.(string); ok {
					switch strings.ToLower(ts) {
					case "critical", "high", "medium", "low":
						return strings.ToLower(ts)
					}
				}
			}
		}
		if level == "" {
			level = rule.DefaultConfig.Level
		}
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	}
	return "unknown"
}

func securitySeverity(props map[string]any) string {
	switch v := props["security-severity"].(type) {
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return SeverityFromScore(f)
		}
		if s := NormalizeSeverity(v); s != "unknown" {
			return s
		}
	case float64:
		return SeverityFromScore(v)
	}
	if v, ok := props["severity"].(string); ok {
		if s := NormalizeSeverity(v); s != "unknown" {
			return s
		}
	}
	return ""
}

// keyValues parses "Key: value" lines (lower-cased keys).
func keyValues(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

var urlRE = regexp.MustCompile(`https?://[^\s)\]]+`)

func firstURL(s string) string { return urlRE.FindString(s) }

var upgradeRE = regexp.MustCompile(`(?i)\bversions?\s+([^\s,;]+(?:\s*,\s*[^\s,;]+)*)`)

// ParseCycloneDX extracts findings from a CycloneDX document's
// vulnerabilities[] (1.4+). Vulnerabilities whose analysis.state is
// not_affected, false_positive or resolved are skipped.
func ParseCycloneDX(b []byte) ([]Finding, error) {
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Group   string `json:"group"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID     string `json:"id"`
			Source struct {
				URL string `json:"url"`
			} `json:"source"`
			Ratings []struct {
				Score    *float64 `json:"score"`
				Severity string   `json:"severity"`
			} `json:"ratings"`
			Description    string `json:"description"`
			Detail         string `json:"detail"`
			Recommendation string `json:"recommendation"`
			Advisories     []struct {
				URL string `json:"url"`
			} `json:"advisories"`
			Affects []struct {
				Ref      string `json:"ref"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				} `json:"versions"`
			} `json:"affects"`
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("invalid CycloneDX document: %w", err)
	}
	if doc.BOMFormat != "" && doc.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("invalid CycloneDX document: bomFormat %q", doc.BOMFormat)
	}
	type comp struct{ name, version string }
	comps := map[string]comp{}
	for _, c := range doc.Components {
		n := c.Name
		if c.Group != "" {
			n = c.Group + "/" + c.Name
		}
		comps[c.BOMRef] = comp{n, c.Version}
	}
	var out []Finding
	for _, v := range doc.Vulnerabilities {
		switch v.Analysis.State {
		case "not_affected", "false_positive", "resolved", "resolved_with_pedigree":
			continue
		}
		sev, rank := "unknown", -1
		for _, r := range v.Ratings {
			s := NormalizeSeverity(r.Severity)
			if s == "unknown" && r.Score != nil {
				s = SeverityFromScore(*r.Score)
			}
			if SeverityRank(s) > rank && s != "unknown" {
				sev, rank = s, SeverityRank(s)
			}
		}
		url := ""
		if len(v.Advisories) > 0 {
			url = v.Advisories[0].URL
		}
		if url == "" {
			url = v.Source.URL
		}
		title := firstLine(v.Description)
		if title == "" {
			title = firstLine(v.Detail)
		}
		fixed := ""
		if m := upgradeRE.FindStringSubmatch(v.Recommendation); m != nil {
			fixed = m[1]
		}
		base := Finding{VulnID: v.ID, Severity: sev, Title: title, URL: url}
		if len(v.Affects) == 0 {
			out = append(out, base)
			continue
		}
		for _, a := range v.Affects {
			f := base
			if c, ok := comps[a.Ref]; ok {
				f.Package, f.InstalledVersion = c.name, c.version
			} else if name, version, ok := purlNameVersion(a.Ref); ok {
				f.Package, f.InstalledVersion = name, version
			} else {
				f.Package = a.Ref
			}
			for _, av := range a.Versions {
				switch av.Status {
				case "unaffected":
					if f.FixedVersion == "" {
						f.FixedVersion = av.Version
					}
				case "affected", "":
					if f.InstalledVersion == "" {
						f.InstalledVersion = av.Version
					}
				}
			}
			if f.FixedVersion == "" {
				f.FixedVersion = fixed
			}
			out = append(out, f)
		}
	}
	return Dedupe(out), nil
}

// purlNameVersion extracts "namespace/name" and version from a purl.
func purlNameVersion(p string) (string, string, bool) {
	if !strings.HasPrefix(p, "pkg:") {
		return "", "", false
	}
	p = strings.TrimPrefix(p, "pkg:")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	_, rest, ok := strings.Cut(p, "/")
	if !ok {
		return "", "", false
	}
	name, version, _ := strings.Cut(rest, "@")
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		name, version = rest[:i], rest[i+1:]
	}
	return unescape(name), unescape(version), true
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
