package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- scanners ---------------------------------------------------------------

// Scanner is a configured vulnerability scanner. Config holds the driver
// settings (secret fields sealed) and rescanIntervalHours.
type Scanner struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

const scannerCols = `id, name, type, config, enabled, created_at, updated_at`

func scanScanner(row interface{ Scan(...any) error }) (*Scanner, error) {
	var s Scanner
	err := row.Scan(&s.ID, &s.Name, &s.Type, &s.Config, &s.Enabled, &s.CreatedAt, &s.UpdatedAt)
	return &s, err
}

func (s *Store) ListScanners(ctx context.Context) ([]*Scanner, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scannerCols+` FROM scanners ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list scanners")
	}
	defer rows.Close()
	out := []*Scanner{}
	for rows.Next() {
		sc, err := scanScanner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) GetScanner(ctx context.Context, name string) (*Scanner, error) {
	sc, err := scanScanner(s.pool.QueryRow(ctx, `SELECT `+scannerCols+` FROM scanners WHERE name=$1`, name))
	return sc, mapErr(err, "scanner "+name)
}

func (s *Store) GetScannerByID(ctx context.Context, id string) (*Scanner, error) {
	sc, err := scanScanner(s.pool.QueryRow(ctx, `SELECT `+scannerCols+` FROM scanners WHERE id=$1`, id))
	return sc, mapErr(err, "scanner "+id)
}

func (s *Store) CreateScanner(ctx context.Context, sc *Scanner) (*Scanner, error) {
	out, err := scanScanner(s.pool.QueryRow(ctx, `INSERT INTO scanners (name, type, config, enabled)
		VALUES ($1,$2,$3,$4) RETURNING `+scannerCols, sc.Name, sc.Type, sc.Config, sc.Enabled))
	return out, mapErr(err, "create scanner "+sc.Name)
}

func (s *Store) UpdateScanner(ctx context.Context, sc *Scanner) (*Scanner, error) {
	out, err := scanScanner(s.pool.QueryRow(ctx, `UPDATE scanners SET type=$2, config=$3, enabled=$4, updated_at=now()
		WHERE name=$1 RETURNING `+scannerCols, sc.Name, sc.Type, sc.Config, sc.Enabled))
	return out, mapErr(err, "scanner "+sc.Name)
}

func (s *Store) DeleteScanner(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scanners WHERE name=$1`, name)
	if err != nil {
		return mapErr(err, "delete scanner "+name)
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "scanner "+name)
	}
	return nil
}

// ---- jobs -------------------------------------------------------------------

// ScanJob is a queued, running or finished scan of a component by a scanner.
type ScanJob struct {
	ID           string     `json:"id"`
	ComponentID  string     `json:"componentId"`
	ScannerID    string     `json:"scannerId"`
	Scanner      string     `json:"scanner"`
	ScannerType  string     `json:"scannerType"`
	Component    string     `json:"component"`
	Version      string     `json:"version"`
	RepositoryID string     `json:"repositoryId"`
	Repository   string     `json:"repository"`
	Status       string     `json:"status"`
	Reason       string     `json:"reason"`
	Attempts     int        `json:"attempts"`
	RunAfter     time.Time  `json:"runAfter"`
	LockedBy     string     `json:"lockedBy"`
	LockedUntil  *time.Time `json:"lockedUntil,omitempty"`
	Error        string     `json:"error"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
	// ContentRev is the component content revision the job scans (set when
	// it is claimed).
	ContentRev int64 `json:"-"`
	tokenSet   bool
}

// HasToken reports whether a webhook callback token is set on the job.
func (j *ScanJob) HasToken() bool { return j.tokenSet }

const jobSelect = `SELECT j.id, j.component_id, j.scanner_id, s.name, s.type, c.name, c.version, c.repository_id, r.name,
	j.status, j.reason, j.attempts, j.run_after, j.locked_by, j.locked_until, j.error, j.created_at, j.updated_at,
	j.finished_at, j.token_hash IS NOT NULL, j.content_rev
	FROM scan_jobs j JOIN scanners s ON s.id = j.scanner_id JOIN components c ON c.id = j.component_id
	JOIN repositories r ON r.id = c.repository_id`

func scanJob(row interface{ Scan(...any) error }) (*ScanJob, error) {
	var j ScanJob
	err := row.Scan(&j.ID, &j.ComponentID, &j.ScannerID, &j.Scanner, &j.ScannerType, &j.Component, &j.Version,
		&j.RepositoryID, &j.Repository, &j.Status, &j.Reason, &j.Attempts, &j.RunAfter, &j.LockedBy, &j.LockedUntil,
		&j.Error, &j.CreatedAt, &j.UpdatedAt, &j.FinishedAt, &j.tokenSet, &j.ContentRev)
	return &j, err
}

func collectJobs(rows pgx.Rows, err error) ([]*ScanJob, error) {
	if err != nil {
		return nil, mapErr(err, "query scan jobs")
	}
	defer rows.Close()
	out := []*ScanJob{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// EnqueueScans queues one job per scanner (by name; disabled or unknown
// scanners are skipped) unless the component already has an outstanding job
// for that scanner. A never-scanned component is marked pending. It is a
// single statement, cheap enough for upload hooks, and returns the number of
// jobs inserted.
func (s *Store) EnqueueScans(ctx context.Context, componentID string, scanners []string, reason string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `WITH ins AS (
			INSERT INTO scan_jobs (component_id, scanner_id, reason)
			SELECT $1, sc.id, $3 FROM scanners sc WHERE sc.name = ANY($2) AND sc.enabled
			ON CONFLICT (component_id, scanner_id) WHERE status IN ('queued', 'running') DO NOTHING
			RETURNING id
		), upd AS (
			UPDATE components SET scan_state = 'pending'
			WHERE id = $1 AND scan_state = 'unscanned' AND EXISTS (SELECT 1 FROM ins)
		)
		SELECT count(*) FROM ins`, componentID, scanners, reason).Scan(&n)
	return n, mapErr(err, "enqueue scans")
}

// MarkComponentPending sets a component's stored state to pending (keeping
// a quarantine in force) because its content changed and it is scanned
// again. It returns false if it was already pending.
func (s *Store) MarkComponentPending(ctx context.Context, componentID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE components SET scan_state='pending' WHERE id=$1 AND scan_state <> 'pending'`, componentID)
	if err != nil {
		return false, mapErr(err, "mark component pending")
	}
	return tag.RowsAffected() == 1, nil
}

// OutstandingJobs returns the queued/running jobs of a component (optionally
// restricted to scanner names).
func (s *Store) OutstandingJobs(ctx context.Context, componentID string, scanners []string) ([]*ScanJob, error) {
	var names any
	if scanners != nil {
		names = scanners
	}
	return collectJobs(s.pool.Query(ctx, jobSelect+` WHERE j.component_id=$1 AND j.status IN ('queued','running')
		AND ($2::text[] IS NULL OR s.name = ANY($2)) ORDER BY s.name`, componentID, names))
}

// ClaimScanJob takes the next ready job (FOR UPDATE SKIP LOCKED), marks it
// running, leases it to worker until now()+lease and records the component
// content revision it is about to scan.
func (s *Store) ClaimScanJob(ctx context.Context, worker string, lease time.Duration) (*ScanJob, error) {
	var id string
	err := s.pool.QueryRow(ctx, `UPDATE scan_jobs SET status='running', locked_by=$1,
			locked_until = now() + make_interval(secs => $2), attempts = attempts + 1, token_hash = NULL, updated_at = now(),
			content_rev = (SELECT c.content_rev FROM components c WHERE c.id = scan_jobs.component_id)
		WHERE id = (SELECT id FROM scan_jobs WHERE status='queued' AND run_after <= now()
			ORDER BY run_after LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id`, worker, lease.Seconds()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapErr(err, "claim scan job")
	}
	return s.GetScanJob(ctx, id)
}

func (s *Store) GetScanJob(ctx context.Context, id string) (*ScanJob, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, jobSelect+` WHERE j.id=$1`, id))
	return j, mapErr(err, "scan job "+id)
}

// ExtendScanLease extends the lease of a running job held by worker. It
// returns false when the job is no longer held (lease expired and reclaimed).
func (s *Store) ExtendScanLease(ctx context.Context, id, worker string, lease time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE scan_jobs SET locked_until = now() + make_interval(secs => $3), updated_at=now()
		WHERE id=$1 AND locked_by=$2 AND status='running'`, id, worker, lease.Seconds())
	if err != nil {
		return false, mapErr(err, "extend lease")
	}
	return tag.RowsAffected() == 1, nil
}

// AwaitScanCallback hands a running job from worker to a webhook scanner:
// the job stays running, owned by "webhook", until the callback arrives or
// the deadline passes.
func (s *Store) AwaitScanCallback(ctx context.Context, id, worker string, tokenHash []byte, deadline time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE scan_jobs SET locked_by='webhook', token_hash=$3,
			locked_until = now() + make_interval(secs => $4), updated_at=now()
		WHERE id=$1 AND locked_by=$2 AND status='running'`, id, worker, tokenHash, deadline.Seconds())
	if err != nil {
		return false, mapErr(err, "await callback")
	}
	return tag.RowsAffected() == 1, nil
}

// RequeueScanJob gives a running job held by worker back to the queue
// without counting the attempt (worker shutdown).
func (s *Store) RequeueScanJob(ctx context.Context, id, worker string) error {
	_, err := s.pool.Exec(ctx, `UPDATE scan_jobs SET status='queued', attempts=greatest(attempts-1, 0),
		locked_by='', locked_until=NULL, updated_at=now() WHERE id=$1 AND status='running' AND locked_by=$2`, id, worker)
	return mapErr(err, "requeue scan job")
}

// ScanJobByToken returns the running webhook job id whose token hash matches.
func (s *Store) ScanJobByToken(ctx context.Context, id string, tokenHash []byte) (*ScanJob, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, jobSelect+` WHERE j.id=$1 AND j.token_hash=$2 AND j.status='running'
		AND j.locked_until > now()`, id, tokenHash))
	return j, mapErr(err, "scan job "+id)
}

// ScanFinding is one vulnerability reported by a scan.
type ScanFinding struct {
	VulnID           string `json:"vulnId"`
	Severity         string `json:"severity"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	Title            string `json:"title"`
	URL              string `json:"url"`
}

// ScanResult is the outcome of one scan.
type ScanResult struct {
	ID          string          `json:"id"`
	ComponentID string          `json:"componentId"`
	ScannerID   string          `json:"scannerId"`
	Scanner     string          `json:"scanner"`
	JobID       *string         `json:"jobId,omitempty"`
	Status      string          `json:"status"`
	Summary     json.RawMessage `json:"summary"`
	ScannedAt   time.Time       `json:"scannedAt"`
	Findings    []ScanFinding   `json:"findings"`
	// ContentRev is the component content revision that was scanned.
	ContentRev int64 `json:"-"`
}

// JobOwner identifies who may complete a running job: the worker holding
// the lease, or the webhook presenting the job token.
type JobOwner struct {
	Worker    string
	TokenHash []byte
}

func (o JobOwner) cond() (string, any) {
	if o.TokenHash != nil {
		return `token_hash = $2`, o.TokenHash
	}
	return `locked_by = $2`, o.Worker
}

// CompleteScanJob records the result of a running job owned by owner and
// marks it done. It returns ErrNotFound when the job is no longer owned (the
// lease expired and another worker reclaimed it).
func (s *Store) CompleteScanJob(ctx context.Context, jobID string, owner JobOwner, res *ScanResult) (*ScanResult, error) {
	if res.Summary == nil {
		res.Summary = json.RawMessage(`{}`)
	}
	cond, arg := owner.cond()
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var compID, scannerID string
		err := tx.QueryRow(ctx, `UPDATE scan_jobs SET status='done', locked_by='', locked_until=NULL, token_hash=NULL,
			error='', finished_at=now(), updated_at=now()
			WHERE id=$1 AND status='running' AND `+cond+` RETURNING component_id, scanner_id`, jobID, arg).Scan(&compID, &scannerID)
		if err != nil {
			return err
		}
		res.ComponentID, res.ScannerID, res.JobID = compID, scannerID, &jobID
		return insertResult(ctx, tx, res)
	})
	if err != nil {
		return nil, mapErr(err, "complete scan job "+jobID)
	}
	return res, nil
}

func insertResult(ctx context.Context, tx pgx.Tx, res *ScanResult) error {
	// The result covers the revision its job scanned (a result without a job
	// covers the current one).
	if err := tx.QueryRow(ctx, `INSERT INTO scan_results (component_id, scanner_id, job_id, status, summary, content_rev)
		VALUES ($1,$2,$3,$4,$5, coalesce((SELECT content_rev FROM scan_jobs WHERE id=$3),
			(SELECT content_rev FROM components WHERE id=$1), 0))
		RETURNING id, scanned_at, content_rev`, res.ComponentID, res.ScannerID, res.JobID, res.Status, res.Summary).
		Scan(&res.ID, &res.ScannedAt, &res.ContentRev); err != nil {
		return err
	}
	if len(res.Findings) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(res.Findings))
	for _, f := range res.Findings {
		rows = append(rows, []any{res.ID, f.VulnID, f.Severity, f.Package, f.InstalledVersion, f.FixedVersion, f.Title, f.URL})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_findings"},
		[]string{"result_id", "vuln_id", "severity", "package", "installed_version", "fixed_version", "title", "url"},
		pgx.CopyFromRows(rows))
	return err
}

// FailScanJob releases a running job after an error: it is queued again
// with run_after = now()+backoff, or marked failed once attempts reach
// maxAttempts (finalResult, if non-nil, is then recorded). It returns the
// job's new status, or ErrNotFound when the job is no longer owned.
func (s *Store) FailScanJob(ctx context.Context, jobID string, owner JobOwner, msg string, maxAttempts int,
	backoff time.Duration, finalResult *ScanResult) (string, error) {
	cond, arg := owner.cond()
	var status string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var compID, scannerID string
		err := tx.QueryRow(ctx, `UPDATE scan_jobs SET
				status = CASE WHEN attempts >= $4 THEN 'failed' ELSE 'queued' END,
				run_after = CASE WHEN attempts >= $4 THEN run_after ELSE now() + make_interval(secs => $5) END,
				finished_at = CASE WHEN attempts >= $4 THEN now() END,
				locked_by='', locked_until=NULL, token_hash=NULL, error=$3, updated_at=now()
			WHERE id=$1 AND status='running' AND `+cond+` RETURNING status, component_id, scanner_id`,
			jobID, arg, msg, maxAttempts, backoff.Seconds()).Scan(&status, &compID, &scannerID)
		if err != nil {
			return err
		}
		if status == "failed" && finalResult != nil {
			finalResult.ComponentID, finalResult.ScannerID, finalResult.JobID = compID, scannerID, &jobID
			if finalResult.Summary == nil {
				finalResult.Summary = json.RawMessage(`{}`)
			}
			return insertResult(ctx, tx, finalResult)
		}
		return nil
	})
	return status, mapErr(err, "fail scan job "+jobID)
}

// ExpiredScanJobs returns running jobs whose lease (or webhook deadline)
// has passed.
func (s *Store) ExpiredScanJobs(ctx context.Context, limit int) ([]*ScanJob, error) {
	return collectJobs(s.pool.Query(ctx, jobSelect+` WHERE j.status='running' AND j.locked_until < now()
		ORDER BY j.locked_until LIMIT $1`, limit))
}

// ReleaseExpiredScanJob applies FailScanJob to a job whose lease expired
// (whatever its holder), provided it is still expired.
func (s *Store) ReleaseExpiredScanJob(ctx context.Context, jobID, msg string, maxAttempts int, backoff time.Duration,
	finalResult *ScanResult) (string, error) {
	var status string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var compID, scannerID string
		err := tx.QueryRow(ctx, `UPDATE scan_jobs SET
				status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'queued' END,
				run_after = CASE WHEN attempts >= $3 THEN run_after ELSE now() + make_interval(secs => $4) END,
				finished_at = CASE WHEN attempts >= $3 THEN now() END,
				locked_by='', locked_until=NULL, token_hash=NULL, error=$2, updated_at=now()
			WHERE id=$1 AND status='running' AND locked_until < now() RETURNING status, component_id, scanner_id`,
			jobID, msg, maxAttempts, backoff.Seconds()).Scan(&status, &compID, &scannerID)
		if err != nil {
			return err
		}
		if status == "failed" && finalResult != nil {
			finalResult.ComponentID, finalResult.ScannerID, finalResult.JobID = compID, scannerID, &jobID
			if finalResult.Summary == nil {
				finalResult.Summary = json.RawMessage(`{}`)
			}
			return insertResult(ctx, tx, finalResult)
		}
		return nil
	})
	return status, mapErr(err, "release scan job "+jobID)
}

// ListScanJobs lists jobs, newest first, optionally by status.
func (s *Store) ListScanJobs(ctx context.Context, status string, limit int) ([]*ScanJob, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	return collectJobs(s.pool.Query(ctx, jobSelect+` WHERE ($1 = '' OR j.status = $1) ORDER BY j.created_at DESC LIMIT $2`,
		status, limit))
}

// ComponentScanJobs lists a component's most recent jobs.
func (s *Store) ComponentScanJobs(ctx context.Context, componentID string, limit int) ([]*ScanJob, error) {
	if limit <= 0 {
		limit = 20
	}
	return collectJobs(s.pool.Query(ctx, jobSelect+` WHERE j.component_id=$1 ORDER BY j.created_at DESC LIMIT $2`,
		componentID, limit))
}

// LatestScanResults returns the most recent result of each scanner for a
// component, with findings.
func (s *Store) LatestScanResults(ctx context.Context, componentID string) ([]*ScanResult, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (r.scanner_id) r.id, r.component_id, r.scanner_id, s.name, r.job_id,
			r.status, r.summary, r.scanned_at, r.content_rev
		FROM scan_results r JOIN scanners s ON s.id = r.scanner_id
		WHERE r.component_id=$1 ORDER BY r.scanner_id, r.scanned_at DESC`, componentID)
	if err != nil {
		return nil, mapErr(err, "latest scan results")
	}
	var out []*ScanResult
	byID := map[string]*ScanResult{}
	for rows.Next() {
		var r ScanResult
		if err := rows.Scan(&r.ID, &r.ComponentID, &r.ScannerID, &r.Scanner, &r.JobID, &r.Status, &r.Summary, &r.ScannedAt,
			&r.ContentRev); err != nil {
			rows.Close()
			return nil, err
		}
		r.Findings = []ScanFinding{}
		out = append(out, &r)
		byID[r.ID] = &r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(out))
	for _, r := range out {
		ids = append(ids, r.ID)
	}
	frows, err := s.pool.Query(ctx, `SELECT result_id, vuln_id, severity, package, installed_version, fixed_version, title, url
		FROM scan_findings WHERE result_id = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, mapErr(err, "scan findings")
	}
	defer frows.Close()
	for frows.Next() {
		var rid string
		var f ScanFinding
		if err := frows.Scan(&rid, &f.VulnID, &f.Severity, &f.Package, &f.InstalledVersion, &f.FixedVersion, &f.Title, &f.URL); err != nil {
			return nil, err
		}
		if r := byID[rid]; r != nil {
			r.Findings = append(r.Findings, f)
		}
	}
	return out, frows.Err()
}

// LatestFindings returns, for each component, the findings of its latest ok
// result of every scanner. Components without findings are absent. It takes
// two indexed reads whatever the number of components.
func (s *Store) LatestFindings(ctx context.Context, componentIDs []string) (map[string][]ScanFinding, error) {
	out := map[string][]ScanFinding{}
	if len(componentIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (component_id, scanner_id) id, component_id
			FROM scan_results WHERE component_id = ANY($1) AND status = 'ok'
			ORDER BY component_id, scanner_id, scanned_at DESC)
		SELECT l.component_id, f.vuln_id, f.severity, f.package, f.installed_version, f.fixed_version, f.title, f.url
		FROM latest l JOIN scan_findings f ON f.result_id = l.id
		ORDER BY l.component_id, f.id`, componentIDs)
	if err != nil {
		return nil, mapErr(err, "latest findings")
	}
	defer rows.Close()
	for rows.Next() {
		var cid string
		var f ScanFinding
		if err := rows.Scan(&cid, &f.VulnID, &f.Severity, &f.Package, &f.InstalledVersion, &f.FixedVersion, &f.Title, &f.URL); err != nil {
			return nil, err
		}
		out[cid] = append(out[cid], f)
	}
	return out, rows.Err()
}

// SetComponentScanState stores the evaluated verdict of a component and
// notifies ChannelScanVerdict (downloads held for the verdict, in any
// process, wake up).
func (s *Store) SetComponentScanState(ctx context.Context, id, state string, quarantined bool, scannedAt *time.Time) error {
	_, err := s.pool.Exec(ctx, `WITH u AS (
			UPDATE components SET scan_state=$2, quarantined=$3, scanned_at=$4 WHERE id=$1 RETURNING id)
		SELECT pg_notify('`+ChannelScanVerdict+`', id::text) FROM u`,
		id, state, quarantined, scannedAt)
	return mapErr(err, "set scan state")
}

// PrioritizeJobs moves the queued, ready jobs of components to the front of
// the queue (a download is waiting for them). Jobs waiting out a retry
// backoff are left alone. It returns the number of jobs moved.
func (s *Store) PrioritizeJobs(ctx context.Context, componentIDs []string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE scan_jobs SET run_after = now() - interval '1 day', updated_at = now()
		WHERE component_id = ANY($1) AND status = 'queued' AND run_after <= now() AND run_after > now() - interval '1 day'`,
		componentIDs)
	if err != nil {
		return 0, mapErr(err, "prioritize scan jobs")
	}
	return int(tag.RowsAffected()), nil
}

// QuarantineStatus is the denormalised scan verdict used at download time.
type QuarantineStatus struct {
	ComponentID string
	Name        string
	Version     string
	ScanState   string
	Quarantined bool
	ScannedAt   *time.Time
}

// ComponentQuarantine reads the verdict of one component.
func (s *Store) ComponentQuarantine(ctx context.Context, componentID string) (*QuarantineStatus, error) {
	var q QuarantineStatus
	err := s.pool.QueryRow(ctx, `SELECT id, name, version, scan_state, quarantined, scanned_at FROM components WHERE id=$1`,
		componentID).Scan(&q.ComponentID, &q.Name, &q.Version, &q.ScanState, &q.Quarantined, &q.ScannedAt)
	return &q, mapErr(err, "component "+componentID)
}

// ManifestQuarantine returns the verdicts of components whose Docker tags
// (under tagPrefix) point at digest, plus quarantined components of image
// whose latest scan covered digest (platform manifests of an index).
func (s *Store) ManifestQuarantine(ctx context.Context, repoID, image, tagPrefix, digest string) ([]*QuarantineStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.id, c.name, c.version, c.scan_state, c.quarantined, c.scanned_at
		FROM assets t JOIN components c ON c.id = t.component_id
		WHERE t.repository_id=$1 AND t.path LIKE $2 AND t.digest=$3
		UNION
		SELECT c.id, c.name, c.version, c.scan_state, c.quarantined, c.scanned_at FROM components c
		WHERE c.repository_id=$1 AND c.name=$4 AND c.quarantined AND EXISTS (
			SELECT 1 FROM scan_results r WHERE r.component_id=c.id AND r.summary->'digests' ? $3)
		LIMIT 50`, repoID, likePrefix(tagPrefix), digest, image)
	if err != nil {
		return nil, mapErr(err, "manifest quarantine")
	}
	defer rows.Close()
	var out []*QuarantineStatus
	for rows.Next() {
		var q QuarantineStatus
		if err := rows.Scan(&q.ComponentID, &q.Name, &q.Version, &q.ScanState, &q.Quarantined, &q.ScannedAt); err != nil {
			return nil, err
		}
		out = append(out, &q)
	}
	return out, rows.Err()
}

// SkippedManifest is a component whose latest scan by some scanner left out
// a platform manifest (not cached by the proxy at the time).
type SkippedManifest struct {
	ComponentID string
	// ContentRev is the revision that scan covered.
	ContentRev int64
}

// SkippedManifestComponents returns the components of image whose latest
// result of any scanner lists digest in summary.skippedDigests.
func (s *Store) SkippedManifestComponents(ctx context.Context, repoID, image, digest string) ([]SkippedManifest, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.component_id, l.content_rev FROM (
			SELECT DISTINCT ON (r.component_id, r.scanner_id) r.component_id, r.content_rev, r.summary
			FROM scan_results r JOIN components c ON c.id = r.component_id
			WHERE c.repository_id=$1 AND c.name=$2
			ORDER BY r.component_id, r.scanner_id, r.scanned_at DESC) l
		WHERE l.summary->'skippedDigests' ? $3 LIMIT 50`, repoID, image, digest)
	if err != nil {
		return nil, mapErr(err, "skipped manifests")
	}
	defer rows.Close()
	var out []SkippedManifest
	for rows.Next() {
		var m SkippedManifest
		if err := rows.Scan(&m.ComponentID, &m.ContentRev); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// BumpContentRev increments a component's content revision if it is still
// rev, and reports whether it did (concurrent callers bump it once).
func (s *Store) BumpContentRev(ctx context.Context, componentID string, rev int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE components SET content_rev = content_rev + 1, updated_at = now()
		WHERE id=$1 AND content_rev=$2`, componentID, rev)
	if err != nil {
		return false, mapErr(err, "bump content revision")
	}
	return tag.RowsAffected() == 1, nil
}

// RescanCandidates returns components whose latest result from scanner is
// older than age and that have no outstanding job for it.
func (s *Store) RescanCandidates(ctx context.Context, scannerID string, age time.Duration, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.component_id FROM (
			SELECT DISTINCT ON (component_id) component_id, scanned_at FROM scan_results
			WHERE scanner_id=$1 ORDER BY component_id, scanned_at DESC) l
		WHERE l.scanned_at < now() - make_interval(secs => $2)
		AND NOT EXISTS (SELECT 1 FROM scan_jobs j WHERE j.component_id=l.component_id AND j.scanner_id=$1
			AND j.status IN ('queued','running'))
		ORDER BY l.scanned_at LIMIT $3`, scannerID, age.Seconds(), limit)
	if err != nil {
		return nil, mapErr(err, "rescan candidates")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RetryCandidates returns components with no outstanding job for scanner
// whose latest result from it is an error older than errorAge, or covers an
// older content revision than the component's (a rescan that never got
// queued). errorAge <= 0 skips errors.
// RetryCandidate is a component RetryCandidates selected; Errored is true
// when its latest result is an error (otherwise it is stale).
type RetryCandidate struct {
	ComponentID string
	Errored     bool
}

func (s *Store) RetryCandidates(ctx context.Context, scannerID string, errorAge time.Duration, limit int) ([]RetryCandidate, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.component_id, l.status = 'error' AND l.content_rev >= c.content_rev FROM (
			SELECT DISTINCT ON (component_id) component_id, status, scanned_at, content_rev FROM scan_results
			WHERE scanner_id=$1 ORDER BY component_id, scanned_at DESC) l
		JOIN components c ON c.id = l.component_id
		WHERE (($2::float8 > 0 AND l.status = 'error' AND l.scanned_at < now() - make_interval(secs => $2::float8)) OR l.content_rev < c.content_rev)
		AND NOT EXISTS (SELECT 1 FROM scan_jobs j WHERE j.component_id=l.component_id AND j.scanner_id=$1
			AND j.status IN ('queued','running'))
		ORDER BY l.scanned_at LIMIT $3`, scannerID, errorAge.Seconds(), limit)
	if err != nil {
		return nil, mapErr(err, "retry candidates")
	}
	defer rows.Close()
	var out []RetryCandidate
	for rows.Next() {
		var c RetryCandidate
		if err := rows.Scan(&c.ComponentID, &c.Errored); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ErroredScanners returns the names of the scanners whose latest result for
// a component is an error.
func (s *Store) ErroredScanners(ctx context.Context, componentID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.name FROM (
			SELECT DISTINCT ON (r.scanner_id) s.name, r.status FROM scan_results r JOIN scanners s ON s.id = r.scanner_id
			WHERE r.component_id=$1 ORDER BY r.scanner_id, r.scanned_at DESC) l
		WHERE l.status = 'error' ORDER BY l.name`, componentID)
	if err != nil {
		return nil, mapErr(err, "errored scanners")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ComponentsWithFindings returns components that have findings for any of
// vulnIDs ("*" = any vulnerability) in one of their results.
func (s *Store) ComponentsWithFindings(ctx context.Context, vulnIDs []string, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT r.component_id FROM scan_findings f JOIN scan_results r ON r.id = f.result_id
		WHERE '*' = ANY($1) OR f.vuln_id = ANY($1) LIMIT $2`, vulnIDs, limit)
	if err != nil {
		return nil, mapErr(err, "components with findings")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---- waivers ----------------------------------------------------------------

// Waiver accepts the risk of a vulnerability for matching components.
type Waiver struct {
	ID                string     `json:"id"`
	VulnID            string     `json:"vulnId"`
	RepositoryPattern string     `json:"repositoryPattern"`
	ComponentPattern  string     `json:"componentPattern"`
	Reason            string     `json:"reason"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	CreatedBy         string     `json:"createdBy"`
	CreatedAt         time.Time  `json:"createdAt"`
}

const waiverCols = `id, vuln_id, repository_pattern, component_pattern, reason, expires_at, created_by, created_at`

func scanWaiver(row interface{ Scan(...any) error }) (*Waiver, error) {
	var w Waiver
	err := row.Scan(&w.ID, &w.VulnID, &w.RepositoryPattern, &w.ComponentPattern, &w.Reason, &w.ExpiresAt, &w.CreatedBy, &w.CreatedAt)
	return &w, err
}

// ListWaivers lists waivers; activeOnly skips expired ones.
func (s *Store) ListWaivers(ctx context.Context, activeOnly bool) ([]*Waiver, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+waiverCols+` FROM waivers
		WHERE NOT $1 OR expires_at IS NULL OR expires_at > now() ORDER BY created_at`, activeOnly)
	if err != nil {
		return nil, mapErr(err, "list waivers")
	}
	defer rows.Close()
	out := []*Waiver{}
	for rows.Next() {
		w, err := scanWaiver(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) GetWaiver(ctx context.Context, id string) (*Waiver, error) {
	w, err := scanWaiver(s.pool.QueryRow(ctx, `SELECT `+waiverCols+` FROM waivers WHERE id=$1`, id))
	return w, mapErr(err, "waiver "+id)
}

func (s *Store) CreateWaiver(ctx context.Context, w *Waiver) (*Waiver, error) {
	out, err := scanWaiver(s.pool.QueryRow(ctx, `INSERT INTO waivers (vuln_id, repository_pattern, component_pattern, reason,
		expires_at, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+waiverCols,
		w.VulnID, w.RepositoryPattern, w.ComponentPattern, w.Reason, w.ExpiresAt, w.CreatedBy))
	return out, mapErr(err, "create waiver")
}

func (s *Store) UpdateWaiver(ctx context.Context, w *Waiver) (*Waiver, error) {
	out, err := scanWaiver(s.pool.QueryRow(ctx, `UPDATE waivers SET vuln_id=$2, repository_pattern=$3, component_pattern=$4,
		reason=$5, expires_at=$6 WHERE id=$1 RETURNING `+waiverCols,
		w.ID, w.VulnID, w.RepositoryPattern, w.ComponentPattern, w.Reason, w.ExpiresAt))
	return out, mapErr(err, "waiver "+w.ID)
}

func (s *Store) DeleteWaiver(ctx context.Context, id string) (*Waiver, error) {
	out, err := scanWaiver(s.pool.QueryRow(ctx, `DELETE FROM waivers WHERE id=$1 RETURNING `+waiverCols, id))
	return out, mapErr(err, "waiver "+id)
}

// WaiversExpiredSince returns waivers that expired in (since, now].
func (s *Store) WaiversExpiredSince(ctx context.Context, since time.Time) ([]*Waiver, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+waiverCols+` FROM waivers WHERE expires_at > $1 AND expires_at <= now()`, since)
	if err != nil {
		return nil, mapErr(err, "expired waivers")
	}
	defer rows.Close()
	var out []*Waiver
	for rows.Next() {
		w, err := scanWaiver(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
