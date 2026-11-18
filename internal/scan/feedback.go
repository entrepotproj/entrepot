package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/gitlab"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/scan/drivers"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// gitlabUpload is the GitLab CI context of an asset upload.
type gitlabUpload struct {
	Instance   string
	ProjectID  string
	SHA        string
	Ref        string
	PipelineID int64
}

func claimString(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case json.Number:
		return v.String()
	}
	return ""
}

// uploadFromGitLab returns the GitLab CI upload of a component's assets
// (the most recently updated one).
func uploadFromGitLab(assets []*store.Asset) *gitlabUpload {
	var best *store.Asset
	var up *gitlabUpload
	for _, a := range assets {
		if len(a.Uploader) < 3 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(a.Uploader, &m) != nil || m["kind"] != "gitlab" {
			continue
		}
		u := &gitlabUpload{Instance: claimString(m, "gitlab"), ProjectID: claimString(m, "project_id"),
			SHA: claimString(m, "sha"), Ref: claimString(m, "ref")}
		u.PipelineID, _ = strconv.ParseInt(claimString(m, "pipeline_id"), 10, 64)
		if u.ProjectID == "" || u.SHA == "" || u.Instance == "" {
			continue
		}
		if best == nil || a.UpdatedAt.After(best.UpdatedAt) {
			best, up = a, u
		}
	}
	return up
}

func (s *Service) gitlabSpec(name string) *config.GitLabSpec {
	for i := range s.Config.Auth.GitLab {
		if s.Config.Auth.GitLab[i].Name == name {
			return &s.Config.Auth.GitLab[i]
		}
	}
	return nil
}

// reportGitLab sends a commit status (and, once all scans finished, merge
// request notes) for components published by GitLab CI jobs. Best effort:
// errors are logged and never fail the scan.
func (s *Service) reportGitLab(comp *store.Component, rp *repo.Repository, v *Verdict) {
	if len(s.Config.Auth.GitLab) == 0 {
		return
	}
	s.feedback.Add(1)
	go func() {
		defer s.feedback.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := s.sendGitLabFeedback(ctx, comp, rp, v); err != nil {
			s.Logger.Warn("gitlab feedback", "repository", rp.Name, "component", describe(comp), "err", err)
		}
	}()
}

// FeedbackWait blocks until pending GitLab feedback calls finished (tests).
func (s *Service) FeedbackWait() { s.feedback.Wait() }

func (s *Service) sendGitLabFeedback(ctx context.Context, comp *store.Component, rp *repo.Repository, v *Verdict) error {
	assets, err := s.Store.ListComponentAssets(ctx, comp.ID)
	if err != nil {
		return err
	}
	up := uploadFromGitLab(assets)
	if up == nil {
		return nil
	}
	spec := s.gitlabSpec(up.Instance)
	if spec == nil {
		return nil
	}
	token, err := spec.API.ResolveToken()
	if err != nil {
		return fmt.Errorf("gitlab %s api token: %w", spec.Name, err)
	}
	if token == "" {
		return nil
	}
	base := spec.API.URL
	if base == "" {
		base = spec.IssuerURL
	}
	c := gitlab.New(base, token, s.HTTP)
	final := v.Outstanding == 0
	failed := v.Quarantined || len(v.Blocking) > 0
	state := "success"
	switch {
	case !final:
		state = "running"
	case failed:
		state = "failed"
	}
	target := ""
	if b := strings.TrimRight(s.URLs.Base, "/"); b != "" {
		target = b + "/components/" + comp.ID
	}
	st := gitlab.CommitStatus{State: state, Name: "entrepot/scan/" + rp.Name, Ref: up.Ref, TargetURL: target,
		Description: statusDescription(comp, v), PipelineID: up.PipelineID}
	if err := c.SetCommitStatus(ctx, up.ProjectID, up.SHA, st); err != nil {
		s.Logger.Warn("gitlab commit status", "project", up.ProjectID, "sha", up.SHA, "err", err)
	}
	if !final {
		return nil
	}
	mrs, err := c.CommitMergeRequests(ctx, up.ProjectID, up.SHA)
	if err != nil {
		return err
	}
	marker := fmt.Sprintf("<!-- entrepot-scan:%s:%s -->", rp.Name, describe(comp))
	body := noteBody(marker, comp, rp, v, target)
	for _, mr := range mrs {
		if mr.State != "" && mr.State != "opened" {
			continue
		}
		pid := up.ProjectID
		if mr.ProjectID != 0 {
			pid = strconv.FormatInt(mr.ProjectID, 10)
		}
		if _, err := c.UpsertMergeRequestNote(ctx, pid, mr.IID, marker, body); err != nil {
			s.Logger.Warn("gitlab merge request note", "project", pid, "mr", mr.IID, "err", err)
		}
	}
	return nil
}

func countsText(c map[string]int) string {
	var parts []string
	for _, sev := range drivers.Severities {
		if n := c[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return strings.Join(parts, ", ")
}

func waivedCount(v *Verdict) int {
	n := 0
	for _, f := range v.Findings {
		if f.Waived {
			n++
		}
	}
	return n
}

func statusDescription(comp *store.Component, v *Verdict) string {
	ref := describe(comp)
	switch {
	case v.Outstanding > 0:
		return ref + ": scanning"
	case v.State == "error":
		return ref + ": scan failed"
	case v.State == "unsupported":
		return ref + ": not scannable"
	}
	d := ref + ": "
	if ct := countsText(v.Counts); ct != "" {
		d += ct
	} else {
		d += "no vulnerabilities"
	}
	if w := waivedCount(v); w > 0 {
		d += fmt.Sprintf(" (%d waived)", w)
	}
	if v.Quarantined {
		d += " - quarantined"
	} else if len(v.Blocking) > 0 {
		d += fmt.Sprintf(" - %d at or above %s", len(v.Blocking), v.Threshold)
	}
	return d
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return s
}

const maxNoteRows = 50

func noteBody(marker string, comp *store.Component, rp *repo.Repository, v *Verdict, target string) string {
	var b strings.Builder
	b.WriteString(marker + "\n")
	icon, verdict := ":white_check_mark:", "no vulnerabilities found"
	switch {
	case v.Quarantined:
		icon, verdict = ":no_entry:", "quarantined — downloads are blocked"
	case len(v.Blocking) > 0:
		icon, verdict = ":x:", fmt.Sprintf("%d vulnerabilities at or above %s", len(v.Blocking), v.Threshold)
	case len(v.Counts) > 0:
		icon, verdict = ":warning:", "vulnerabilities below the "+v.Threshold+" threshold"
	case v.State == "error":
		icon, verdict = ":grey_question:", "scan failed"
	case v.State == "unsupported":
		icon, verdict = ":grey_question:", "this component type cannot be scanned"
	}
	fmt.Fprintf(&b, "### %s Entrepot scan of `%s` in `%s`\n\n", icon, describe(comp), rp.Name)
	fmt.Fprintf(&b, "**Result:** %s", verdict)
	if ct := countsText(v.Counts); ct != "" {
		fmt.Fprintf(&b, " (%s)", ct)
	}
	b.WriteString("\n\n")
	var names []string
	for _, r := range v.Results {
		names = append(names, r.Scanner)
	}
	if len(names) > 0 {
		fmt.Fprintf(&b, "Scanners: %s · policy: %s, threshold %s\n\n", strings.Join(names, ", "), v.Mode, v.Threshold)
	}
	fs := append([]Finding(nil), v.Findings...)
	sortFindings(fs)
	if len(fs) > 0 {
		b.WriteString("| Severity | Vulnerability | Package | Installed | Fixed in | Title |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		seen := map[string]bool{}
		rows := 0
		for _, f := range fs {
			k := f.VulnID + "\x00" + f.Package + "\x00" + f.InstalledVersion
			if seen[k] {
				continue
			}
			seen[k] = true
			if rows == maxNoteRows {
				fmt.Fprintf(&b, "\n_… more findings not shown._\n")
				break
			}
			rows++
			id := mdEscape(f.VulnID)
			if f.URL != "" {
				id = "[" + id + "](" + f.URL + ")"
			}
			sev := f.Severity
			if f.Waived {
				sev = "~~" + sev + "~~ (waived)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", sev, id, mdEscape(f.Package), mdEscape(f.InstalledVersion),
				mdEscape(f.FixedVersion), mdEscape(truncateStr(f.Title, 120)))
		}
	}
	if target != "" {
		fmt.Fprintf(&b, "\n[View in Entrepot](%s)\n", target)
	}
	return b.String()
}
