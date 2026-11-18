// Package scan implements the component scanning pipeline.
//
// Components are queued for scanning (scan_jobs) when they are uploaded or
// first cached by a proxy, on demand, and periodically for rescans. Workers
// claim jobs with FOR UPDATE SKIP LOCKED under a lease that is extended by
// heartbeats while a scan runs; expired leases are reclaimed and failed
// jobs are retried with exponential backoff. Drivers run the Trivy or Grype
// CLI against a CycloneDX SBOM (packages) or an OCI image layout (Docker
// images), or hand the job to a webhook scanner that calls back with
// results. Each completed job stores a scan_results row with findings; the
// component verdict (scan_state, quarantined) is derived from the latest
// result of every scanner minus active waivers, and is what the download
// gate (repo.Service.QuarantineCheck) consults. Results of components
// published by GitLab CI jobs are reported back as commit statuses and
// merge request notes.
package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/config"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// Deps are the services the pipeline uses.
type Deps struct {
	Config  *config.Config
	Store   *store.Store
	Repos   *repo.Service
	Formats *format.Registry
	Secrets *secrets.Box
	URLs    httpx.URLs
	Logger  *slog.Logger
}

// Service is the scanning pipeline. The exported tunables may be changed
// before Run (tests shorten them).
type Service struct {
	Deps

	// MaxAttempts before a job is marked failed (default 3).
	MaxAttempts int
	// RetryBackoff is the delay before the first retry; it doubles with
	// every attempt (default 30s, capped at 1h).
	RetryBackoff time.Duration
	// Lease is how long a worker holds a job between heartbeats (default 2m).
	Lease time.Duration
	// RescanEvery is the scheduler period (default 5m).
	RescanEvery time.Duration
	// RescanBatch bounds rescans enqueued per scanner and period (default 200).
	RescanBatch int
	// ReapEvery is how often expired leases are reclaimed (default 15s).
	ReapEvery time.Duration
	// HTTP is used for webhook scanners and GitLab feedback.
	HTTP *http.Client

	workerID string
	wake     chan struct{}

	mu       sync.Mutex
	reasons  map[string]reasonEntry
	feedback sync.WaitGroup
	// waiverLast is when expired waivers were last looked for.
	waiverLast time.Time
}

func New(d Deps) *Service {
	host, _ := os.Hostname()
	var b [3]byte
	_, _ = rand.Read(b[:])
	return &Service{
		Deps:         d,
		MaxAttempts:  3,
		RetryBackoff: 30 * time.Second,
		Lease:        2 * time.Minute,
		RescanEvery:  5 * time.Minute,
		RescanBatch:  200,
		ReapEvery:    15 * time.Second,
		HTTP:         &http.Client{Timeout: 30 * time.Second},
		workerID:     fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b[:])),
		wake:         make(chan struct{}, 1),
		reasons:      map[string]reasonEntry{},
	}
}

// Attach registers repository hooks: jobs are enqueued when components are
// stored, and downloads pass the quarantine gate.
func (s *Service) Attach() {
	s.Repos.OnComponentStored(s.onStored)
	s.Repos.QuarantineCheck = s.QuarantineCheck
}

// onStored enqueues scans for a stored component (one INSERT).
func (s *Service) onStored(ctx context.Context, ev repo.StoredEvent) {
	sc := ev.Repository.Cfg.Scan
	if !sc.Enabled() || !ev.Changed || ev.ComponentID == "" {
		return
	}
	reason := "upload"
	if ev.Cached {
		if !sc.ScanOnProxyFetch() {
			return
		}
		reason = "proxy"
	} else if !sc.ScanOnUpload() {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	n, err := s.Store.EnqueueScans(ctx, ev.ComponentID, sc.Scanners, reason)
	if err != nil {
		s.Logger.Error("enqueue scan", "repository", ev.Repository.Name, "component", ev.ComponentID, "err", err)
		return
	}
	if n > 0 {
		s.notify()
	}
}

// Enqueue queues scans of a component by the named scanners and returns
// its outstanding jobs for them.
func (s *Service) Enqueue(ctx context.Context, componentID string, scanners []string, reason string) ([]*store.ScanJob, error) {
	n, err := s.Store.EnqueueScans(ctx, componentID, scanners, reason)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		s.notify()
	}
	return s.Store.OutstandingJobs(ctx, componentID, scanners)
}

func (s *Service) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run starts the workers (scan.workers of them), the rescan scheduler and
// the lease reaper, and returns when ctx is cancelled and they stopped.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < s.Config.Scan.Workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.worker(ctx, fmt.Sprintf("%s/%d", s.workerID, n))
		}(i)
	}
	if s.Config.Scan.Workers > 0 {
		s.Logger.Info("scan workers started", "workers", s.Config.Scan.Workers, "id", s.workerID)
	}
	wg.Add(2)
	go func() { defer wg.Done(); s.loop(ctx, s.RescanEvery, time.Minute, s.rescanTick) }()
	go func() { defer wg.Done(); s.loop(ctx, s.ReapEvery, s.ReapEvery, s.reapTick) }()
	wg.Wait()
	s.feedback.Wait()
}

func (s *Service) loop(ctx context.Context, every, first time.Duration, fn func(ctx context.Context)) {
	if first > every {
		first = every
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fn(ctx)
		t.Reset(every)
	}
}

func (s *Service) pollInterval() time.Duration {
	if p := s.Config.Scan.PollInterval; p > 0 {
		return p
	}
	return 2 * time.Second
}

func (s *Service) worker(ctx context.Context, id string) {
	for ctx.Err() == nil {
		job, err := s.Store.ClaimScanJob(ctx, id, s.Lease)
		if err != nil {
			if ctx.Err() == nil {
				s.Logger.Error("claim scan job", "err", err)
			}
		}
		if job == nil {
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			case <-time.After(s.pollInterval()):
			}
			continue
		}
		s.process(ctx, id, job)
	}
}

func (s *Service) backoff(attempts int) time.Duration {
	d := s.RetryBackoff
	for i := 1; i < attempts && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

func (s *Service) rescanTick(ctx context.Context) {
	if _, err := s.RescanNow(ctx); err != nil && ctx.Err() == nil {
		s.Logger.Error("schedule rescans", "err", err)
	}
}

// RescanNow enqueues rescans for components whose latest result from a
// scanner with rescanIntervalHours > 0 is older than that interval (at most
// RescanBatch per scanner). It returns the number of jobs queued.
func (s *Service) RescanNow(ctx context.Context) (int, error) {
	scanners, err := s.Store.ListScanners(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, sc := range scanners {
		cfg, err := ParseScannerConfig(sc.Config)
		if err != nil || !sc.Enabled || cfg.RescanIntervalHours <= 0 {
			continue
		}
		ids, err := s.Store.RescanCandidates(ctx, sc.ID, time.Duration(cfg.RescanIntervalHours)*time.Hour, s.RescanBatch)
		if err != nil {
			return total, err
		}
		for _, id := range ids {
			c, err := s.Store.GetComponent(ctx, id)
			if err != nil {
				continue
			}
			rp, err := s.Repos.Get(ctx, c.Repository)
			if err != nil || !rp.Cfg.Scan.Enabled() || !contains(rp.Cfg.Scan.Scanners, sc.Name) {
				continue
			}
			n, err := s.Store.EnqueueScans(ctx, id, []string{sc.Name}, "rescan")
			if err != nil {
				return total, err
			}
			total += n
		}
	}
	if total > 0 {
		s.Logger.Info("rescans queued", "jobs", total)
		s.notify()
	}
	return total, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
