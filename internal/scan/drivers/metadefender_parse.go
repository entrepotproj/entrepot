package drivers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MetaDefender Core analysis results (GET /file/{data_id}, GET /hash/{hash};
// OpenAPI "AnalysisResult", Core 5.x). Only the fields Entrepot uses.
type mdResult struct {
	DataID   string `json:"data_id"`
	FileInfo struct {
		SHA256       string   `json:"sha256"`
		DisplayName  string   `json:"display_name"`
		TypeCategory []string `json:"type_category"`
	} `json:"file_info"`
	ProcessInfo struct {
		// Result is Allowed, Blocked or Processing.
		Result             string   `json:"result"`
		BlockedReason      string   `json:"blocked_reason"`
		BlockedReasons     []string `json:"blocked_reasons"`
		ProgressPercentage int      `json:"progress_percentage"`
		// Profile is the rule (workflow) the file was processed with.
		Profile      string   `json:"profile"`
		OutdatedData []string `json:"outdated_data"`
	} `json:"process_info"`
	ScanResults struct {
		// ScanAllResultI indexes the Processing Results table (0 no threat,
		// 1 infected, 2 suspicious, 3 failed, 255 in progress, ...).
		ScanAllResultI     *int                    `json:"scan_all_result_i"`
		ScanAllResultA     string                  `json:"scan_all_result_a"`
		ProgressPercentage int                     `json:"progress_percentage"`
		StartTime          string                  `json:"start_time"`
		TotalAVs           int                     `json:"total_avs"`
		ScanDetails        map[string]mdEngineScan `json:"scan_details"`
	} `json:"scan_results"`
	ExtractedFiles json.RawMessage `json:"extracted_files"`
}

type mdEngineScan struct {
	ThreatFound string `json:"threat_found"`
	ScanResultI int    `json:"scan_result_i"`
	DefTime     string `json:"def_time"`
}

// MetaDefender processing result codes Entrepot distinguishes.
const (
	mdNoThreat      = 0
	mdInfected      = 1
	mdSuspicious    = 2
	mdFailed        = 3
	mdCancelled     = 19
	mdPUA           = 22
	mdSandboxSusp   = 26
	mdSandboxLikely = 27
	mdSandboxMal    = 28
	mdGlobalTimeout = 31
	mdKnownBad      = 38
	mdTIBlocked     = 61
	mdAIMalicious   = 68
	mdDownloadTO    = 70
	mdDownloadFail  = 71
	mdInProgress    = 255
)

func (r *mdResult) code() int {
	if r.ScanResults.ScanAllResultI == nil {
		return -1
	}
	return *r.ScanResults.ScanAllResultI
}

// done reports whether the analysis has finished.
func (r *mdResult) done() bool {
	if strings.EqualFold(r.ProcessInfo.Result, "Processing") || r.code() == mdInProgress || r.code() >= 256 {
		return false
	}
	p := r.ProcessInfo.ProgressPercentage
	if p == 0 {
		p = r.ScanResults.ProgressPercentage
	}
	return p >= 100
}

// startTime parses scan_results.start_time (RFC 3339 or Unix ms).
func (r *mdResult) startTime() (time.Time, bool) {
	v := strings.TrimSpace(r.ScanResults.StartTime)
	if v == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z0700", "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	var ms int64
	if _, err := fmt.Sscan(v, &ms); err == nil && ms > 0 {
		return time.UnixMilli(ms), true
	}
	return time.Time{}, false
}

// threat is the most frequent threat name among the engines (ties broken
// alphabetically, so it stays the same across rescans and exact waivers
// keep matching), the number of engines that reported one, and the newest
// engine definition date.
func (r *mdResult) threat() (name string, detected int, newestDefs string) {
	counts := map[string]int{}
	for _, e := range r.ScanResults.ScanDetails {
		if t := strings.TrimSpace(e.ThreatFound); t != "" && e.ScanResultI != mdNoThreat && e.ScanResultI != mdFailed {
			counts[t]++
			detected++
		}
		if e.DefTime > newestDefs {
			newestDefs = e.DefTime
		}
	}
	best := 0
	for t, n := range counts {
		if n > best || (n == best && t < name) {
			name, best = t, n
		}
	}
	return name, detected, newestDefs
}

// errMDIncomplete is returned for analyses that did not finish (failed,
// cancelled, timed out): the job is retried.
type errMDIncomplete struct{ msg string }

func (e errMDIncomplete) Error() string { return e.msg }

// mdVerdict maps a finished analysis to findings. ok with no findings is a
// clean file. An error means the analysis cannot be trusted (unknown result,
// failed analysis) and the scan is retried.
func mdVerdict(r *mdResult, file File, webURL string) ([]Finding, error) {
	code := r.code()
	switch code {
	case mdFailed, mdCancelled, mdGlobalTimeout, mdDownloadTO, mdDownloadFail:
		return nil, errMDIncomplete{fmt.Sprintf("MetaDefender could not analyse %s: %s", file.Name, firstNonEmpty(r.ScanResults.ScanAllResultA, fmt.Sprint(code)))}
	}
	threat, detected, _ := r.threat()
	label := file.Label
	if label == "" {
		label = file.Name
	}
	mk := func(prefix, what, severity string) Finding {
		title := fmt.Sprintf("%s: %d/%d engines", firstNonEmpty(r.ScanResults.ScanAllResultA, "Blocked"), detected, r.ScanResults.TotalAVs)
		if r.ScanResults.TotalAVs == 0 {
			title = firstNonEmpty(r.ScanResults.ScanAllResultA, strings.Join(r.ProcessInfo.BlockedReasons, ", "), "Blocked")
		}
		return Finding{VulnID: truncate(prefix+what, 200), Severity: severity, Package: label,
			InstalledVersion: short(file.SHA256), Title: title, URL: mdLink(webURL, r.DataID)}
	}
	switch strings.ToLower(r.ProcessInfo.Result) {
	case "blocked":
		switch code {
		case mdInfected, mdSandboxMal, mdKnownBad, mdTIBlocked, mdAIMalicious:
			return []Finding{mk(ThreatMalware, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "infected"), "critical")}, nil
		case mdSuspicious, mdSandboxSusp, mdSandboxLikely:
			return []Finding{mk(ThreatSuspicious, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "suspicious"), "critical")}, nil
		case mdPUA:
			return []Finding{mk(ThreatPUA, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "potentially unwanted"), "critical")}, nil
		}
		reason := firstNonEmpty(r.ProcessInfo.BlockedReason, strings.Join(r.ProcessInfo.BlockedReasons, ", "), r.ScanResults.ScanAllResultA, "blocked")
		return []Finding{mk(ThreatBlocked, reason, "critical")}, nil
	case "allowed":
		switch code {
		case mdInfected, mdSandboxMal, mdKnownBad, mdAIMalicious:
			// The rule allowed an infected file; Entrepot still reports it.
			return []Finding{mk(ThreatMalware, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "infected"), "critical")}, nil
		case mdSuspicious, mdSandboxSusp, mdSandboxLikely:
			return []Finding{mk(ThreatSuspicious, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "suspicious"), "high")}, nil
		case mdPUA:
			return []Finding{mk(ThreatPUA, firstNonEmpty(threat, r.ScanResults.ScanAllResultA, "potentially unwanted"), "high")}, nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected MetaDefender result %q for %s", r.ProcessInfo.Result, file.Name)
}

// mdBlockedLeaves is GET /file/{data_id}/blocked-leaves.
type mdBlockedLeaves struct {
	Details []struct {
		BlockedReasons []string `json:"blocked_reasons"`
		Engines        []struct {
			Engine     string `json:"engine"`
			ThreatName string `json:"threat_name"`
		} `json:"engines"`
		DataID      string `json:"data_id"`
		DisplayName string `json:"display_name"`
		Path        string `json:"path"`
	} `json:"details"`
}

// maxLeafFindings bounds the findings for the blocked files of an archive.
const maxLeafFindings = 20

// leafFindings turns the blocked files inside an archive into findings
// (path inside the archive, most frequent threat name).
func leafFindings(bl *mdBlockedLeaves, file File, parent []Finding, webURL string) []Finding {
	if bl == nil || len(bl.Details) == 0 || len(parent) == 0 {
		return parent
	}
	label := file.Label
	if label == "" {
		label = file.Name
	}
	var out []Finding
	for i, d := range bl.Details {
		if i == maxLeafFindings {
			break
		}
		counts := map[string]int{}
		for _, e := range d.Engines {
			if t := strings.TrimSpace(e.ThreatName); t != "" {
				counts[t]++
			}
		}
		names := make([]string, 0, len(counts))
		for t := range counts {
			names = append(names, t)
		}
		sort.Slice(names, func(i, j int) bool {
			if counts[names[i]] != counts[names[j]] {
				return counts[names[i]] > counts[names[j]]
			}
			return names[i] < names[j]
		})
		prefix := ThreatBlocked
		reason := strings.Join(d.BlockedReasons, ", ")
		for _, r := range d.BlockedReasons {
			switch strings.ToLower(r) {
			case "infected":
				prefix = ThreatMalware
			case "suspicious":
				if prefix != ThreatMalware {
					prefix = ThreatSuspicious
				}
			case "potentially unwanted":
				if prefix == ThreatBlocked {
					prefix = ThreatPUA
				}
			}
		}
		what := reason
		if len(names) > 0 && prefix != ThreatBlocked {
			what = names[0]
		}
		inner := leafPath(firstNonEmpty(d.Path, d.DisplayName), file.Name)
		out = append(out, Finding{VulnID: truncate(prefix+firstNonEmpty(what, "blocked"), 200), Severity: "critical",
			Package: truncate(label+" › "+inner, 500), InstalledVersion: short(file.SHA256),
			Title: firstNonEmpty(reason, "Blocked") + " inside the archive", URL: mdLink(webURL, firstNonEmpty(d.DataID, parent[0].URL))})
	}
	return out
}

// leafPath is a path inside an archive, with "/" separators and without
// the archive's own name (MetaDefender reports archive.zip\\dir\\file).
func leafPath(p, archive string) string {
	p = strings.Trim(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"), "/")
	if archive != "" {
		if rest, ok := strings.CutPrefix(p, archive+"/"); ok {
			p = rest
		}
	}
	return p
}

// mdLink fills {dataId} in the configured web URL template.
func mdLink(tmpl, dataID string) string {
	if tmpl == "" || dataID == "" {
		return ""
	}
	if strings.HasPrefix(dataID, "http://") || strings.HasPrefix(dataID, "https://") {
		return dataID
	}
	return strings.ReplaceAll(tmpl, "{dataId}", dataID)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
