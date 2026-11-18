package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/match"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/scan/drivers"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// Finding is a stored finding annotated with the scanner and waiver.
type Finding struct {
	store.ScanFinding
	Scanner  string `json:"scanner"`
	Waived   bool   `json:"waived"`
	WaiverID string `json:"waiverId,omitempty"`
}

// Verdict is the evaluated scan status of a component.
type Verdict struct {
	State       string
	Quarantined bool
	ScannedAt   *time.Time
	// Results are the latest result per scanner.
	Results []*store.ScanResult
	// Findings of all latest results (waived ones marked).
	Findings []Finding
	// Counts of unwaived findings by severity.
	Counts map[string]int
	// Blocking are unwaived findings at or above the threshold.
	Blocking []Finding
	// Outstanding is the number of queued/running jobs.
	Outstanding int
	Mode        string
	Threshold   string
	// Reason explains a quarantine.
	Reason string
}

// Unwaived returns the findings not covered by a waiver.
func (v *Verdict) Unwaived() []Finding {
	var out []Finding
	for _, f := range v.Findings {
		if !f.Waived {
			out = append(out, f)
		}
	}
	return out
}

// WaiverMatches reports whether waiver w covers vuln in component
// name@version of repository repoName. Patterns use internal/match globs;
// "*" (the default) matches everything, including names with '/'.
func WaiverMatches(w *store.Waiver, repoName, name, version, vuln string) bool {
	if w.ExpiresAt != nil && !w.ExpiresAt.After(time.Now()) {
		return false
	}
	if w.VulnID != "*" && !strings.EqualFold(w.VulnID, vuln) {
		return false
	}
	if p := w.RepositoryPattern; p != "" && p != "*" && p != "**" && !match.Glob(p, repoName) {
		return false
	}
	p := w.ComponentPattern
	if p == "" || p == "*" || p == "**" {
		return true
	}
	return match.Glob(p, name) || match.Glob(p, name+"@"+version) || match.Glob(p, name+":"+version)
}

// verdict computes (without storing) a component's verdict.
func (s *Service) verdict(ctx context.Context, comp *store.Component, rp *repo.Repository) (*Verdict, error) {
	results, err := s.Store.LatestScanResults(ctx, comp.ID)
	if err != nil {
		return nil, err
	}
	waivers, err := s.Store.ListWaivers(ctx, true)
	if err != nil {
		return nil, err
	}
	jobs, err := s.Store.OutstandingJobs(ctx, comp.ID, nil)
	if err != nil {
		return nil, err
	}
	sc := rp.Cfg.Scan
	v := &Verdict{Results: results, Counts: map[string]int{}, Outstanding: len(jobs), Mode: sc.EffectiveMode(), Threshold: sc.Threshold()}
	if sc == nil {
		v.Mode = "off"
	}
	thr := drivers.SeverityRank(v.Threshold)
	var ok, errored, unsupported int
	seen := map[string]bool{}
	for _, r := range results {
		if v.ScannedAt == nil || r.ScannedAt.After(*v.ScannedAt) {
			t := r.ScannedAt
			v.ScannedAt = &t
		}
		switch r.Status {
		case "ok":
			ok++
		case "unsupported":
			unsupported++
			continue
		default:
			errored++
			continue
		}
		for _, f := range r.Findings {
			ef := Finding{ScanFinding: f, Scanner: r.Scanner}
			for _, w := range waivers {
				if WaiverMatches(w, comp.Repository, comp.Name, comp.Version, f.VulnID) {
					ef.Waived, ef.WaiverID = true, w.ID
					break
				}
			}
			v.Findings = append(v.Findings, ef)
			if ef.Waived {
				continue
			}
			// Count a vulnerability once even if several scanners report it.
			k := f.VulnID + "\x00" + f.Package + "\x00" + f.InstalledVersion
			if !seen[k] {
				seen[k] = true
				v.Counts[f.Severity]++
				if drivers.SeverityRank(f.Severity) >= thr && thr > 0 {
					v.Blocking = append(v.Blocking, ef)
				}
			}
		}
	}
	switch {
	case len(results) == 0 && v.Outstanding > 0:
		v.State = "pending"
	case len(results) == 0:
		v.State = "unscanned"
	case ok > 0 && len(v.Counts) > 0:
		v.State = "vulnerable"
	case ok > 0:
		v.State = "clean"
	case errored > 0:
		v.State = "error"
	default:
		v.State = "unsupported"
	}
	v.Quarantined = v.Mode == "quarantine" && len(v.Blocking) > 0
	if v.Quarantined {
		v.Reason = quarantineReason(comp, v.Blocking)
	}
	return v, nil
}

func quarantineReason(comp *store.Component, blocking []Finding) string {
	sortFindings(blocking)
	f := blocking[0]
	where := describe(comp)
	if f.Package != "" && f.Package != comp.Name {
		where = strings.TrimSpace(f.Package+" "+f.InstalledVersion) + " in " + where
	}
	msg := fmt.Sprintf("%s (%s) in %s", f.VulnID, f.Severity, where)
	if len(blocking) > 1 {
		msg += fmt.Sprintf(" and %d more", len(blocking)-1)
	}
	return msg + " — waive or fix to download"
}

func sortFindings(fs []Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && less(fs[j], fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func less(a, b Finding) bool {
	if ra, rb := drivers.SeverityRank(a.Severity), drivers.SeverityRank(b.Severity); ra != rb {
		return ra > rb
	}
	return a.VulnID < b.VulnID
}

// Evaluate recomputes and stores a component's verdict.
func (s *Service) Evaluate(ctx context.Context, componentID string) (*Verdict, *store.Component, *repo.Repository, error) {
	unlock, err := s.Store.AdvisoryLock(ctx, "scan-eval:"+componentID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer unlock()
	comp, err := s.Store.GetComponent(ctx, componentID)
	if err != nil {
		return nil, nil, nil, err
	}
	rp, err := s.Repos.GetByID(ctx, comp.RepositoryID)
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := s.verdict(ctx, comp, rp)
	if err != nil {
		return nil, nil, nil, err
	}
	if v.State != comp.ScanState || v.Quarantined != comp.Quarantined || !sameTime(v.ScannedAt, comp.ScannedAt) {
		if err := s.Store.SetComponentScanState(ctx, comp.ID, v.State, v.Quarantined, v.ScannedAt); err != nil {
			return nil, nil, nil, err
		}
		comp.ScanState, comp.Quarantined, comp.ScannedAt = v.State, v.Quarantined, v.ScannedAt
	}
	s.mu.Lock()
	delete(s.reasons, comp.ID)
	delete(s.reasons, "recheck:"+comp.ID)
	s.mu.Unlock()
	return v, comp, rp, nil
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// ReevaluateVulns re-evaluates (bounded) components with findings for the
// given vulnerability ids ("*" = any), after waivers changed.
func (s *Service) ReevaluateVulns(ctx context.Context, vulnIDs []string) int {
	ids, err := s.Store.ComponentsWithFindings(ctx, vulnIDs, 2000)
	if err != nil {
		s.Logger.Error("find components to re-evaluate", "err", err)
		return 0
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		if _, _, _, err := s.Evaluate(ctx, id); err != nil {
			s.Logger.Warn("re-evaluate component", "component", id, "err", err)
		}
	}
	return len(ids)
}

// ComponentVerdict computes a component's current verdict (for the API).
func (s *Service) ComponentVerdict(ctx context.Context, comp *store.Component) (*Verdict, error) {
	rp, err := s.Repos.GetByID(ctx, comp.RepositoryID)
	if err != nil {
		return nil, err
	}
	return s.verdict(ctx, comp, rp)
}

type reasonEntry struct {
	reason  string
	expires time.Time
}

// QuarantineCheck is the download gate (repo.Service.QuarantineCheck). In
// quarantine mode it blocks quarantined components and, with
// blockUntilScanned, components without a completed scan. Docker layer
// blobs are never blocked; manifests are blocked through the tags that
// point at them (or the index they belong to).
func (s *Service) QuarantineCheck(ctx context.Context, rp *repo.Repository, a *store.Asset) (bool, string) {
	sc := rp.Cfg.Scan
	if !sc.Enabled() || sc.EffectiveMode() != "quarantine" {
		return false, ""
	}
	var statuses []*store.QuarantineStatus
	switch {
	case a.ComponentID != nil:
		q, err := s.Store.ComponentQuarantine(ctx, *a.ComponentID)
		if err != nil {
			s.Logger.Warn("quarantine check", "asset", a.ID, "err", err)
			return false, ""
		}
		statuses = []*store.QuarantineStatus{q}
	case rp.Format == "docker" && strings.Contains(a.Path, "/_manifests/"):
		image := a.Path[:strings.Index(a.Path, "/_manifests/")]
		qs, err := s.Store.ManifestQuarantine(ctx, rp.ID, image, image+"/_tags/", a.Digest)
		if err != nil {
			s.Logger.Warn("quarantine check", "asset", a.ID, "err", err)
			return false, ""
		}
		statuses = qs
	default:
		return false, ""
	}
	for _, q := range statuses {
		if q.Quarantined {
			return true, s.reasonFor(ctx, q)
		}
		// The verdict was stored under another mode or threshold (the
		// repository settings changed): check it again (cached briefly).
		if q.ScanState == "vulnerable" {
			if blocked, reason := s.recheck(ctx, q); blocked {
				return true, reason
			}
		}
	}
	if sc.BlockUntilScanned {
		for _, q := range statuses {
			if q.ScanState == "unscanned" || q.ScanState == "pending" {
				ref := q.Name + "@" + q.Version
				if rp.Format == "docker" {
					ref = q.Name + ":" + q.Version
				}
				if q.ScanState == "unscanned" {
					// Content stored before scanning was enabled: scan it now.
					if _, err := s.Store.EnqueueScans(context.WithoutCancel(ctx), q.ComponentID, sc.Scanners, "rescan"); err == nil {
						s.notify()
					}
				}
				return true, ref + " has not been scanned yet; downloads are blocked until the scan completes"
			}
		}
	}
	return false, ""
}

// recheck evaluates a vulnerable, not quarantined component again; the
// answer is cached for 30s and a changed verdict is stored.
func (s *Service) recheck(ctx context.Context, q *store.QuarantineStatus) (bool, string) {
	key := "recheck:" + q.ComponentID
	s.mu.Lock()
	e, ok := s.reasons[key]
	s.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.reason != "", e.reason
	}
	reason := ""
	if comp, err := s.Store.GetComponent(ctx, q.ComponentID); err == nil {
		if v, err := s.ComponentVerdict(ctx, comp); err == nil && v.Quarantined {
			reason = v.Reason
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, _, _, _ = s.Evaluate(ctx, q.ComponentID)
			}()
		}
	}
	s.mu.Lock()
	s.reasons[key] = reasonEntry{reason: reason, expires: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return reason != "", reason
}

func (s *Service) reasonFor(ctx context.Context, q *store.QuarantineStatus) string {
	s.mu.Lock()
	e, ok := s.reasons[q.ComponentID]
	s.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.reason
	}
	reason := "vulnerabilities at or above the severity threshold in " + q.Name + "@" + q.Version + " — waive or fix to download"
	if comp, err := s.Store.GetComponent(ctx, q.ComponentID); err == nil {
		if v, err := s.ComponentVerdict(ctx, comp); err == nil && v.Reason != "" {
			reason = v.Reason
		}
	}
	s.mu.Lock()
	if len(s.reasons) > 10000 {
		s.reasons = map[string]reasonEntry{}
	}
	s.reasons[q.ComponentID] = reasonEntry{reason: reason, expires: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return reason
}
