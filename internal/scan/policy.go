package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/match"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/scan/drivers"
	"github.com/entrepotproj/entrepot/internal/store"
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
	// Strict is true when the repository's verdicts wait for every
	// configured scanner (blockOnError, or a file scanner configured).
	Strict    bool
	Mode      string
	Threshold string
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
	if w.VulnID == "*" {
		// Threats (malware, policy blocks) are only waived by their exact id.
		if drivers.IsThreat(vuln) {
			return false
		}
	} else if !strings.EqualFold(w.VulnID, vuln) {
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
	configured, strict, err := s.strictConfig(ctx, sc)
	if err != nil {
		return nil, err
	}
	v.Strict = strict
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
	// Strict verdicts: a configured scanner that hasn't scanned the current
	// content and has a job outstanding keeps the component pending; one
	// whose current result is an error makes it error (with blockOnError).
	awaited, failed := false, false
	if strict {
		current := map[string]*store.ScanResult{}
		for _, r := range results {
			if configured[r.Scanner] && r.ContentRev >= comp.ContentRev {
				current[r.Scanner] = r
			}
		}
		outstanding := map[string]bool{}
		for _, j := range jobs {
			outstanding[j.Scanner] = true
		}
		for name := range configured {
			r := current[name]
			switch {
			case outstanding[name] && (r == nil || r.Status == "error"):
				awaited = true
			case r != nil && r.Status == "error":
				failed = true
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
	case awaited:
		v.State = "pending"
	case failed && sc.BlockOnError:
		v.State = "error"
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
	if drivers.IsThreat(f.VulnID) {
		return threatReason(comp, f, len(blocking)-1)
	}
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

// threatReason describes a blocking threat found by a file scanner.
func threatReason(comp *store.Component, f Finding, more int) string {
	where := describe(comp)
	if f.Package != "" {
		where = f.Package + " (" + where + ")"
	}
	var msg string
	if drivers.FindingKind(f.VulnID) == "policy" {
		msg = fmt.Sprintf("%s refused %s: %s", f.Scanner, where, strings.TrimPrefix(f.VulnID, drivers.ThreatBlocked))
	} else {
		msg = fmt.Sprintf("%s detected by %s in %s", f.VulnID, f.Scanner, where)
	}
	if more > 0 {
		msg += fmt.Sprintf(" and %d more", more)
	}
	return msg + " — downloads are blocked; only a waiver for this exact finding releases it"
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
	// Threats before vulnerabilities of the same severity.
	if ta, tb := drivers.IsThreat(a.VulnID), drivers.IsThreat(b.VulnID); ta != tb {
		return ta
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
		s.holds.signal(comp.ID)
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
// blockUntilScanned, components without a completed scan (and, with
// blockOnError, whose scan failed). Docker layer blobs are never blocked;
// manifests are blocked through the tags that point at them (or the index
// they belong to). With holdSeconds, a download of content that is still
// being scanned waits for the verdict; if the hold runs out the client is
// asked to retry (503).
func (s *Service) QuarantineCheck(ctx context.Context, rp *repo.Repository, a *store.Asset) repo.GateDecision {
	d, pending := s.gate(ctx, rp, a)
	if len(pending) == 0 {
		return d
	}
	hold := rp.Cfg.Scan.HoldTimeout()
	if hold <= 0 {
		return d
	}
	// Sidecars (PyPI .metadata, Helm .prov) are derived from the package:
	// clients fetch them while resolving, often for many versions, so they
	// are served while the package is scanned rather than held. A
	// quarantine still blocks them (gate decides that above).
	if repo.IsSidecar(rp.Format, a.Path) {
		return repo.GateDecision{}
	}
	return s.hold(ctx, rp, a, pending, hold)
}

// gate decides a download now. pending lists the components it waits for:
// not scanned yet, or failed with a retry outstanding.
func (s *Service) gate(ctx context.Context, rp *repo.Repository, a *store.Asset) (repo.GateDecision, []string) {
	sc := rp.Cfg.Scan
	if !sc.Enabled() || sc.EffectiveMode() != "quarantine" {
		return repo.GateDecision{}, nil
	}
	var statuses []*store.QuarantineStatus
	switch {
	case a.ComponentID != nil:
		q, err := s.Store.ComponentQuarantine(ctx, *a.ComponentID)
		if err != nil {
			s.Logger.Warn("quarantine check", "asset", a.ID, "err", err)
			return repo.GateDecision{}, nil
		}
		statuses = []*store.QuarantineStatus{q}
	case rp.Format == "docker" && strings.Contains(a.Path, "/_manifests/"):
		image := a.Path[:strings.Index(a.Path, "/_manifests/")]
		qs, err := s.Store.ManifestQuarantine(ctx, rp.ID, image, image+"/_tags/", a.Digest)
		if err != nil {
			s.Logger.Warn("quarantine check", "asset", a.ID, "err", err)
			return repo.GateDecision{}, nil
		}
		statuses = qs
	default:
		return repo.GateDecision{}, nil
	}
	for _, q := range statuses {
		if q.Quarantined {
			return repo.GateDecision{Blocked: true, Reason: s.reasonFor(ctx, q)}, nil
		}
		// The verdict was stored under another mode or threshold (the
		// repository settings changed): check it again (cached briefly).
		if q.ScanState == "vulnerable" {
			if blocked, reason := s.recheck(ctx, q); blocked {
				return repo.GateDecision{Blocked: true, Reason: reason}, nil
			}
		}
	}
	if sc.BlockOnError {
		for _, q := range statuses {
			if q.ScanState != "error" {
				continue
			}
			// Retry the failed scans on demand, at most once a minute (the
			// retry loop also does, every scan.errorRetryInterval).
			if q.ScannedAt == nil || time.Since(*q.ScannedAt) > time.Minute {
				s.retryFailed(ctx, q.ComponentID)
			}
			d := repo.GateDecision{Blocked: true, Reason: refOf(rp, q) + " could not be scanned; downloads are blocked until a scan succeeds"}
			if jobs, err := s.Store.OutstandingJobs(ctx, q.ComponentID, nil); err == nil && len(jobs) > 0 {
				return d, []string{q.ComponentID}
			}
			return d, nil
		}
	}
	if sc.BlockUntilScanned {
		var pending []string
		reason := ""
		for _, q := range statuses {
			if q.ScanState == "unscanned" || q.ScanState == "pending" {
				if q.ScanState == "unscanned" {
					// Content stored before scanning was enabled: scan it now.
					if n, err := s.Store.EnqueueScans(context.WithoutCancel(ctx), q.ComponentID, sc.Scanners, "rescan"); err == nil && n > 0 {
						s.notifyJobs(ctx)
					}
				}
				if reason == "" {
					reason = refOf(rp, q) + " has not been scanned yet; downloads are blocked until the scan completes"
				}
				pending = append(pending, q.ComponentID)
			}
		}
		if len(pending) > 0 {
			return repo.GateDecision{Blocked: true, Reason: reason}, pending
		}
	}
	return repo.GateDecision{}, nil
}

// hold waits (up to timeout) for the verdict of the pending components and
// decides again. The components' ready jobs go to the front of the queue.
func (s *Service) hold(ctx context.Context, rp *repo.Repository, a *store.Asset, ids []string, timeout time.Duration) repo.GateDecision {
	start := time.Now()
	waiting := func() repo.GateDecision {
		return repo.GateDecision{Pending: true, Reason: "still being scanned; retry shortly"}
	}
	ch, unsubscribe, ok := s.holds.subscribe(ids)
	if !ok {
		holdDuration.WithLabelValues("refused").Observe(0)
		return waiting()
	}
	defer unsubscribe()
	if n, err := s.Store.PrioritizeJobs(context.WithoutCancel(ctx), ids); err == nil && n > 0 {
		s.notifyJobs(ctx)
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := 250 * time.Millisecond
	for {
		pollT := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			pollT.Stop()
			holdDuration.WithLabelValues("cancelled").Observe(time.Since(start).Seconds())
			return waiting()
		case <-s.holds.stop:
			pollT.Stop()
			holdDuration.WithLabelValues("timeout").Observe(time.Since(start).Seconds())
			return waiting()
		case <-deadline.C:
			pollT.Stop()
			holdDuration.WithLabelValues("timeout").Observe(time.Since(start).Seconds())
			return waiting()
		case <-ch:
			pollT.Stop()
		case <-pollT.C:
			if poll < time.Second {
				poll *= 2
			}
		}
		d, pending := s.gate(ctx, rp, a)
		if len(pending) == 0 {
			outcome := "served"
			if d.Blocked {
				outcome = "blocked"
			}
			holdDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
			return d
		}
	}
}

// StopHolds answers held downloads (and later ones) without waiting; called
// when the HTTP server shuts down so draining pods don't hold requests.
func (s *Service) StopHolds() { s.holds.shutdown() }

func refOf(rp *repo.Repository, q *store.QuarantineStatus) string {
	if rp.Format == "docker" {
		return q.Name + ":" + q.Version
	}
	return q.Name + "@" + q.Version
}

// retryFailed queues the scanners whose latest result for a component is
// an error again.
func (s *Service) retryFailed(ctx context.Context, componentID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	names, err := s.Store.ErroredScanners(ctx, componentID)
	if err != nil || len(names) == 0 {
		return
	}
	if n, err := s.Store.EnqueueScans(ctx, componentID, names, "retry"); err == nil && n > 0 {
		s.notifyJobs(ctx)
	}
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
