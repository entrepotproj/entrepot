package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/scan/drivers"
	"github.com/entrepotproj/entrepot/internal/store"
)

// summary is stored in scan_results.summary.
type summary struct {
	Target         string         `json:"target,omitempty"`
	Error          string         `json:"error,omitempty"`
	ScannerVersion string         `json:"scannerVersion,omitempty"`
	DBVersion      string         `json:"dbVersion,omitempty"`
	Counts         map[string]int `json:"counts,omitempty"`
	// Digest is the manifest a Docker tag pointed at when scanned; Digests
	// are all manifests covered (index and platform manifests).
	Digest    string   `json:"digest,omitempty"`
	Digests   []string `json:"digests,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
	// SkippedDigests are platform manifests a proxy had not cached, left
	// out of the scan (pulling one rescans the image in strict repositories).
	SkippedDigests []string `json:"skippedDigests,omitempty"`
	Attempt        int      `json:"attempt,omitempty"`
	// Files records how each file was analysed by a file scanner.
	Files []drivers.FileResult `json:"files,omitempty"`
}

func (sm summary) json() json.RawMessage {
	b, _ := json.Marshal(sm)
	return b
}

func countFindings(fs []drivers.Finding) map[string]int {
	c := map[string]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

func toStoreFindings(fs []drivers.Finding) []store.ScanFinding {
	out := make([]store.ScanFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, store.ScanFinding{VulnID: truncateStr(f.VulnID, 200), Severity: drivers.NormalizeSeverity(f.Severity),
			Package: truncateStr(f.Package, 500), InstalledVersion: truncateStr(f.InstalledVersion, 200),
			FixedVersion: truncateStr(f.FixedVersion, 500), Title: truncateStr(f.Title, 500), URL: truncateStr(f.URL, 1000)})
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// jobContext bundles what processing a job needs.
type jobContext struct {
	job     *store.ScanJob
	scanner *loadedScanner
	target  *target
}

func (s *Service) jobTimeout(ls *loadedScanner) time.Duration {
	sec := 0
	switch {
	case ls.Cfg.Trivy != nil:
		sec = ls.Cfg.Trivy.TimeoutSeconds
	case ls.Cfg.Grype != nil:
		sec = ls.Cfg.Grype.TimeoutSeconds
	case ls.Type == TypeMetaDefender:
		return ls.Cfg.MetaDefender.Timeout()
	}
	if sec > 0 {
		return time.Duration(sec) * time.Second
	}
	if t := s.Config.Scan.JobTimeout; t > 0 {
		return t
	}
	return 15 * time.Minute
}

// process runs one claimed job.
func (s *Service) process(ctx context.Context, worker string, job *store.ScanJob) {
	owner := store.JobOwner{Worker: worker}
	log := s.Logger.With("job", job.ID, "scanner", job.Scanner, "repository", job.Repository,
		"component", job.Component+"@"+job.Version, "attempt", job.Attempts)
	sc, err := s.Store.GetScannerByID(ctx, job.ScannerID)
	if err != nil {
		s.fail(ctx, job, owner, "", err)
		return
	}
	ls, err := s.loadScanner(sc)
	if err != nil {
		s.fail(ctx, job, owner, "", err)
		return
	}
	if !ls.Enabled {
		// Not an error of the component: drop the job without a result.
		if _, err := s.Store.FailScanJob(ctx, job.ID, owner, "scanner is disabled", 0, 0, nil); err != nil {
			log.Warn("drop job of disabled scanner", "err", err)
		}
		return
	}
	comp, err := s.Store.GetComponent(ctx, job.ComponentID)
	if err != nil {
		s.fail(ctx, job, owner, "", err)
		return
	}
	rp, err := s.Repos.GetByID(ctx, comp.RepositoryID)
	if err != nil {
		s.fail(ctx, job, owner, "", err)
		return
	}
	var tg *target
	if isFileScanner(ls.Type) {
		tg, err = s.fileTarget(ctx, rp, comp)
	} else {
		tg, err = s.resolveTarget(ctx, rp, comp)
	}
	if err != nil {
		s.fail(ctx, job, owner, "", err)
		return
	}
	if tg.kind == kindUnsupported {
		s.complete(ctx, job, owner, &store.ScanResult{Status: "unsupported",
			Summary: summary{Target: tg.description, Error: tg.reason, Attempt: job.Attempts}.json()})
		return
	}
	if ls.Type == TypeWebhook {
		s.dispatchWebhook(ctx, worker, job, ls, rp, comp, tg)
		return
	}
	log.Info("scanning", "target", tg.description)
	start := time.Now()

	// Heartbeat: keep the lease while the scanner runs; stop if it is lost.
	scanCtx, cancel := context.WithTimeout(ctx, s.jobTimeout(ls))
	defer cancel()
	var lost bool
	var hbMu sync.Mutex
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		every := s.Lease / 3
		if every < 50*time.Millisecond {
			every = 50 * time.Millisecond
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-t.C:
				ok, err := s.Store.ExtendScanLease(ctx, job.ID, worker, s.Lease)
				if err == nil && !ok {
					hbMu.Lock()
					lost = true
					hbMu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	o, sm, err := s.runDriver(scanCtx, ls, rp, comp, tg, job)
	cancel()
	<-hbDone
	hbMu.Lock()
	wasLost := lost
	hbMu.Unlock()
	if wasLost {
		log.Warn("scan lease lost; result discarded")
		return
	}
	if err != nil {
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			err = fmt.Errorf("scan timed out after %s: %w", s.jobTimeout(ls), err)
		}
		if ctx.Err() != nil {
			// Shutting down: give the job back without counting the attempt.
			s.release(job, owner)
			return
		}
		log.Warn("scan failed", "err", err)
		s.fail(ctx, job, owner, tg.description, err)
		return
	}
	sm.Attempt = job.Attempts
	res := &store.ScanResult{Status: o.Status, Summary: sm.json(), Findings: toStoreFindings(o.Findings)}
	log.Info("scan complete", "findings", len(o.Findings), "duration", time.Since(start).Round(time.Millisecond))
	s.complete(ctx, job, owner, res)
}

// release returns a job to the queue (worker shutdown).
func (s *Service) release(job *store.ScanJob, owner store.JobOwner) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Store.RequeueScanJob(ctx, job.ID, owner.Worker); err != nil {
		s.Logger.Warn("release scan job", "job", job.ID, "err", err)
	}
}

// runDriver materialises the target and runs a CLI driver, or streams the
// files to a file scanner.
func (s *Service) runDriver(ctx context.Context, ls *loadedScanner, rp *repo.Repository, comp *store.Component, tg *target,
	job *store.ScanJob) (*drivers.Outcome, summary, error) {
	sm := summary{Target: tg.description}
	if tg.kind == drivers.KindFiles {
		md, err := s.metaDefender(ls)
		if err != nil {
			return nil, sm, err
		}
		o, err := md.Scan(ctx, drivers.Target{Kind: drivers.KindFiles, Files: tg.files, Description: tg.description})
		if err != nil {
			return nil, sm, err
		}
		sm.ScannerVersion, sm.DBVersion, sm.Counts, sm.Files = o.ScannerVersion, o.DBVersion, countFindings(o.Findings), o.Files
		if tg.digest != "" {
			sm.Digest, sm.Digests, sm.SkippedDigests = tg.digest, []string{tg.digest}, tg.skipped
			for _, m := range tg.platforms {
				if m.Digest != tg.digest {
					sm.Digests = append(sm.Digests, m.Digest)
				}
				if m.Platform != "" {
					sm.Platforms = append(sm.Platforms, m.Platform)
				}
			}
		}
		return o, sm, nil
	}
	dir, err := s.workDir(job.ID)
	if err != nil {
		return nil, sm, err
	}
	defer os.RemoveAll(dir)
	drv := s.driver(ls, dir)
	switch tg.kind {
	case drivers.KindPackage:
		path := filepath.Join(dir, "sbom.cdx.json")
		if err := drivers.WriteSBOM(path, tg.pkg, tg.distro); err != nil {
			return nil, sm, err
		}
		o, err := drv.Scan(ctx, drivers.Target{Kind: drivers.KindPackage, PURL: tg.purl, Distro: tg.distro,
			SBOMPath: path, Description: tg.description})
		if err != nil {
			return nil, sm, err
		}
		sm.ScannerVersion, sm.DBVersion, sm.Counts = o.ScannerVersion, o.DBVersion, countFindings(o.Findings)
		return o, sm, nil
	case drivers.KindImage:
		exp, err := s.imageExporter()
		if err != nil {
			return nil, sm, err
		}
		sm.Digest = tg.digest
		sm.Digests = []string{tg.digest}
		sm.SkippedDigests = tg.skipped
		total := &drivers.Outcome{Status: drivers.StatusOK}
		for i, m := range tg.platforms {
			ldir := filepath.Join(dir, fmt.Sprintf("image-%d", i))
			if err := exp.ExportImages(ctx, rp, tg.image, []string{m.Digest}, ldir); err != nil {
				return nil, sm, fmt.Errorf("export %s@%s: %w", tg.image, m.Digest, err)
			}
			o, err := drv.Scan(ctx, drivers.Target{Kind: drivers.KindImage, LayoutDir: ldir, Description: tg.description})
			if err != nil {
				return nil, sm, err
			}
			_ = os.RemoveAll(ldir)
			total.Findings = append(total.Findings, o.Findings...)
			total.ScannerVersion, total.DBVersion = o.ScannerVersion, o.DBVersion
			if m.Digest != tg.digest {
				sm.Digests = append(sm.Digests, m.Digest)
			}
			if m.Platform != "" {
				sm.Platforms = append(sm.Platforms, m.Platform)
			}
		}
		total.Findings = drivers.Dedupe(total.Findings)
		sm.ScannerVersion, sm.DBVersion, sm.Counts = total.ScannerVersion, total.DBVersion, countFindings(total.Findings)
		return total, sm, nil
	}
	return nil, sm, fmt.Errorf("unsupported target kind %q", tg.kind)
}

func (s *Service) workDir(jobID string) (string, error) {
	base := s.Config.Scan.WorkDir
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o750); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "entrepot-scan-"+jobID[:8]+"-")
}

func (s *Service) driver(ls *loadedScanner, dir string) drivers.Driver {
	switch ls.Type {
	case TypeGrype:
		g := &drivers.Grype{WorkDir: dir}
		if c := ls.Cfg.Grype; c != nil {
			g.Binary, g.ExtraArgs = c.Binary, c.ExtraArgs
		}
		return g
	default:
		t := &drivers.Trivy{WorkDir: dir}
		if c := ls.Cfg.Trivy; c != nil {
			t.Binary, t.ServerURL, t.ServerToken, t.ExtraArgs = c.Binary, c.ServerURL, c.ServerToken, c.ExtraArgs
		}
		return t
	}
}

// complete stores a result for a job and re-evaluates the component.
func (s *Service) complete(ctx context.Context, job *store.ScanJob, owner store.JobOwner, res *store.ScanResult) {
	if _, err := s.Store.CompleteScanJob(ctx, job.ID, owner, res); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.Logger.Warn("scan job no longer held; result discarded", "job", job.ID)
			return
		}
		s.Logger.Error("store scan result", "job", job.ID, "err", err)
		return
	}
	s.afterResult(ctx, job.ComponentID, res)
}

// fail records a failed attempt (retried with backoff; after MaxAttempts
// the job fails and an error result is stored).
func (s *Service) fail(ctx context.Context, job *store.ScanJob, owner store.JobOwner, target string, cause error) {
	msg := truncateStr(cause.Error(), 2000)
	final := &store.ScanResult{Status: "error", Summary: summary{Target: target, Error: msg, Attempt: job.Attempts}.json()}
	status, err := s.Store.FailScanJob(ctx, job.ID, owner, msg, s.MaxAttempts, s.backoff(job.Attempts), final)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Logger.Error("record scan failure", "job", job.ID, "err", err)
		}
		return
	}
	if status == "failed" {
		s.Logger.Warn("scan job failed permanently", "job", job.ID, "scanner", job.Scanner,
			"component", job.Component+"@"+job.Version, "err", msg)
		s.afterResult(ctx, job.ComponentID, final)
	}
}

// afterResult re-evaluates the component, reports to GitLab and, when the
// content changed while it was being scanned (a file added or replaced, a
// Docker tag moved), queues another scan by the same scanner.
func (s *Service) afterResult(ctx context.Context, componentID string, res *store.ScanResult) {
	// Queue the rescan before evaluating, so a strict verdict sees the job
	// outstanding and stays pending instead of releasing unscanned content.
	if res != nil {
		s.requeueIfStale(ctx, componentID, res)
	}
	v, comp, rp, err := s.Evaluate(ctx, componentID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Logger.Error("evaluate component", "component", componentID, "err", err)
		}
		return
	}
	s.reportGitLab(comp, rp, v)
}

// requeueIfStale queues another scan by res's scanner when res covers older
// content than the component now holds.
func (s *Service) requeueIfStale(ctx context.Context, componentID string, res *store.ScanResult) {
	comp, err := s.Store.GetComponent(ctx, componentID)
	if err != nil || res.ContentRev >= comp.ContentRev {
		return
	}
	rp, err := s.Repos.GetByID(ctx, comp.RepositoryID)
	if err != nil || !rp.Cfg.Scan.Enabled() {
		return
	}
	sc, err := s.Store.GetScannerByID(ctx, res.ScannerID)
	if err != nil || !contains(rp.Cfg.Scan.Scanners, sc.Name) {
		return
	}
	if _, err := s.Enqueue(ctx, comp.ID, []string{sc.Name}, "upload"); err != nil {
		s.Logger.Warn("re-queue changed content", "component", comp.ID, "err", err)
	}
}

func (s *Service) reapTick(ctx context.Context) {
	if _, err := s.ReapNow(ctx); err != nil && ctx.Err() == nil {
		s.Logger.Error("reap scan jobs", "err", err)
	}
}

// ReapNow reclaims jobs whose lease (or webhook callback deadline) expired:
// they are retried, or failed after MaxAttempts. Components affected by
// waivers that expired since the last pass are re-evaluated.
func (s *Service) ReapNow(ctx context.Context) (int, error) {
	jobs, err := s.Store.ExpiredScanJobs(ctx, 100)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, j := range jobs {
		msg := "scan lease expired (worker stopped or stalled)"
		if j.LockedBy == "webhook" {
			msg = "webhook scanner did not report results in time"
		}
		final := &store.ScanResult{Status: "error", Summary: summary{Error: msg, Attempt: j.Attempts}.json()}
		status, err := s.Store.ReleaseExpiredScanJob(ctx, j.ID, msg, s.MaxAttempts, s.backoff(j.Attempts), final)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
		s.Logger.Warn("reclaimed expired scan job", "job", j.ID, "scanner", j.Scanner, "status", status, "heldBy", j.LockedBy)
		if status == "failed" {
			s.afterResult(ctx, j.ComponentID, final)
		} else {
			s.notify()
		}
	}
	s.expireWaivers(ctx)
	return n, nil
}

func (s *Service) expireWaivers(ctx context.Context) {
	s.mu.Lock()
	since := s.waiverLast
	if since.IsZero() {
		since = time.Now().Add(-s.ReapEvery * 2)
	}
	now := time.Now()
	s.mu.Unlock()
	ws, err := s.Store.WaiversExpiredSince(ctx, since)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.waiverLast = now
	s.mu.Unlock()
	var ids []string
	for _, w := range ws {
		ids = append(ids, w.VulnID)
	}
	if len(ids) > 0 {
		s.ReevaluateVulns(ctx, ids)
	}
}

// describe returns "name@version" (or image:tag for Docker).
func describe(c *store.Component) string {
	switch {
	case c.Version == "":
		return c.Name // raw files
	case c.Format == "docker":
		return c.Name + ":" + c.Version
	}
	return c.Name + "@" + c.Version
}
