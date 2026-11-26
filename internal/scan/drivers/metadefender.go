package drivers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// MetaDefender scans the files of a target with OPSWAT MetaDefender Core
// (REST API v5). Each file is looked up by hash (an earlier analysis with
// the same rule and current engine definitions is reused) or uploaded as a
// raw body and polled until the analysis finishes.
//
// Anything MetaDefender does not answer clearly (failed or unfinished
// analyses, unexpected responses) is an error, so the job is retried and,
// with blockOnError, downloads stay blocked.
type MetaDefender struct {
	URL    string
	APIKey string
	// Rule (workflow) to process files with; empty for the server default.
	Rule string
	// Concurrency bounds the files analysed at once (default 4).
	Concurrency int
	// HashLookup reuses earlier analyses no older than MaxResultAge.
	HashLookup   bool
	MaxResultAge time.Duration
	// WebURL links findings to results ({dataId} is replaced).
	WebURL string
	// Client sends the requests; it must not set a total timeout (uploads
	// of large files are bounded by the context).
	Client *http.Client

	// Polling and busy-server backoff (defaults 250ms-2s and 1s).
	PollMin, PollMax time.Duration
	BusyBackoff      time.Duration
}

// MaxConcurrency bounds Concurrency.
const MaxConcurrency = 32

// mdFlight collapses concurrent analyses of the same content (two jobs
// scanning components that share a file, Docker layers shared by tags).
var mdFlight singleflight.Group

// mdDefaultProfiles remembers the rule MetaDefender applied to our uploads
// when no rule is configured, so hash lookups only reuse results of that
// rule.
var mdDefaultProfiles sync.Map // base URL -> profile

type mdAnalysis struct {
	res    *mdResult
	cached bool
}

func (m *MetaDefender) base() string { return strings.TrimRight(m.URL, "/") }

func (m *MetaDefender) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return http.DefaultClient
}

func durOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Scan analyses every file of a KindFiles target.
func (m *MetaDefender) Scan(ctx context.Context, t Target) (*Outcome, error) {
	if t.Kind != KindFiles {
		return nil, fmt.Errorf("metadefender cannot scan %s targets", t.Kind)
	}
	if m.URL == "" {
		return nil, errors.New("metadefender.url is not set")
	}
	out := &Outcome{Status: StatusOK, Files: make([]FileResult, len(t.Files))}
	findings := make([][]Finding, len(t.Files))
	defs := make([]string, len(t.Files))
	g, gctx := errgroup.WithContext(ctx)
	n := m.Concurrency
	if n <= 0 {
		n = 4
	}
	n = min(n, MaxConcurrency)
	g.SetLimit(n)
	for i := range t.Files {
		f := t.Files[i]
		g.Go(func() error {
			a, err := m.analyse(gctx, f)
			if err != nil {
				return err
			}
			fs, err := mdVerdict(a.res, f, m.WebURL)
			if err != nil {
				return err
			}
			if len(fs) > 0 && strings.EqualFold(a.res.ProcessInfo.Result, "blocked") {
				fs = m.withLeaves(gctx, a.res, f, fs)
			}
			_, _, defs[i] = a.res.threat()
			findings[i] = fs
			out.Files[i] = FileResult{Name: firstNonEmpty(f.Label, f.Name), SHA256: strings.ToLower(a.res.FileInfo.SHA256),
				DataID: a.res.DataID, Result: firstNonEmpty(a.res.ScanResults.ScanAllResultA, a.res.ProcessInfo.Result), Cached: a.cached}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for i := range findings {
		out.Findings = append(out.Findings, findings[i]...)
		if defs[i] > out.DBVersion {
			out.DBVersion = defs[i]
		}
	}
	out.Findings = Dedupe(out.Findings)
	if v, _, err := m.Version(ctx); err == nil {
		out.ScannerVersion = v
	}
	return out, nil
}

// analyse returns the finished analysis of one file, shared with
// concurrent analyses of the same content.
func (m *MetaDefender) analyse(ctx context.Context, f File) (*mdAnalysis, error) {
	sum := strings.ToLower(f.SHA256)
	if sum == "" {
		return m.analyseOnce(ctx, f)
	}
	key := m.base() + "\x00" + m.Rule + "\x00" + sum
	ch := mdFlight.DoChan(key, func() (any, error) { return m.analyseOnce(ctx, f) })
	var r singleflight.Result
	select {
	case r = <-ch:
	case <-ctx.Done():
		// When this call runs the analysis it returns shortly with a more
		// precise error (busy server, progress); a shared analysis run
		// for another job may continue.
		t := time.NewTimer(10 * time.Second)
		defer t.Stop()
		select {
		case r = <-ch:
		case <-t.C:
			return nil, fmt.Errorf("MetaDefender did not finish analysing %s: %w", f.Name, ctx.Err())
		}
	}
	if r.Err != nil {
		// The shared analysis may have failed because another job's
		// context ended; analyse again under our own.
		if ctx.Err() == nil && (errors.Is(r.Err, context.Canceled) || errors.Is(r.Err, context.DeadlineExceeded)) {
			return m.analyseOnce(ctx, f)
		}
		return nil, r.Err
	}
	return r.Val.(*mdAnalysis), nil
}

func (m *MetaDefender) analyseOnce(ctx context.Context, f File) (*mdAnalysis, error) {
	if m.HashLookup && f.SHA256 != "" {
		r, err := m.lookup(ctx, f)
		if err != nil {
			return nil, err
		}
		if r != nil {
			return &mdAnalysis{res: r, cached: true}, nil
		}
	}
	id, sent, err := m.upload(ctx, f)
	if err != nil {
		return nil, err
	}
	r, err := m.poll(ctx, id, f)
	if err != nil {
		return nil, err
	}
	got := strings.ToLower(r.FileInfo.SHA256)
	if got == "" {
		return nil, fmt.Errorf("MetaDefender result for %s has no file_info.sha256", f.Name)
	}
	if got != sent || (f.SHA256 != "" && got != strings.ToLower(f.SHA256)) {
		return nil, fmt.Errorf("MetaDefender analysed different content for %s (sha256 %s, sent %s)", f.Name, short(got), short(sent))
	}
	if m.Rule == "" && r.ProcessInfo.Profile != "" {
		mdDefaultProfiles.Store(m.base(), r.ProcessInfo.Profile)
	}
	return &mdAnalysis{res: r}, nil
}

func (m *MetaDefender) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, m.base()+path, body)
	if err != nil {
		return nil, err
	}
	if m.APIKey != "" {
		req.Header.Set("apikey", m.APIKey)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// mdError describes an unexpected answer without echoing large bodies.
func mdError(what string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(b))
	var e struct {
		Err   string `json:"err"`
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && firstNonEmpty(e.Err, e.Error) != "" {
		msg = firstNonEmpty(e.Err, e.Error)
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s: MetaDefender refused the request (%d, check metadefender.apiKey): %s", what, resp.StatusCode, msg)
	}
	if msg == "" {
		return fmt.Errorf("%s: MetaDefender answered %d", what, resp.StatusCode)
	}
	return fmt.Errorf("%s: MetaDefender answered %d: %s", what, resp.StatusCode, truncate(msg, 300))
}

// lookup returns an earlier analysis that can be reused, or nil.
func (m *MetaDefender) lookup(ctx context.Context, f File) (*mdResult, error) {
	req, err := m.newRequest(ctx, http.MethodGet, "/hash/"+url.PathEscape(strings.ToLower(f.SHA256)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("selfonly", "true")
	if h := int(m.MaxResultAge / time.Hour); h > 0 {
		req.Header.Set("timerange", strconv.Itoa(h))
	}
	if m.Rule != "" {
		req.Header.Set("rule", encodeHeader(m.Rule))
	}
	resp, err := m.client().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Lookups only save work: fall back to uploading.
		return nil, nil
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, mdError("hash lookup", resp)
	case resp.StatusCode != http.StatusOK:
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, nil
	}
	var r mdResult
	if json.Unmarshal(b, &r) != nil || r.DataID == "" {
		return nil, nil // {"<HASH>": "Not Found"}
	}
	if !m.reusable(&r, f) {
		return nil, nil
	}
	return &r, nil
}

// reusable reports whether an earlier analysis can stand in for a new one:
// finished and conclusive, of the same content, by the same rule, with
// current engine definitions and recent enough.
func (m *MetaDefender) reusable(r *mdResult, f File) bool {
	if !r.done() || len(r.ProcessInfo.OutdatedData) > 0 {
		return false
	}
	switch r.code() {
	case -1, mdFailed, mdCancelled, mdGlobalTimeout, mdDownloadTO, mdDownloadFail:
		return false
	}
	if !strings.EqualFold(r.FileInfo.SHA256, f.SHA256) {
		return false
	}
	want := m.Rule
	if want == "" {
		p, ok := mdDefaultProfiles.Load(m.base())
		if !ok {
			return false // learn the default rule from an upload first
		}
		want = p.(string)
	}
	if r.ProcessInfo.Profile != want {
		return false
	}
	st, ok := r.startTime()
	if !ok {
		return false
	}
	age := durOr(m.MaxResultAge, 24*time.Hour)
	return time.Since(st) <= age
}

// hashingReader hashes and counts what is read.
type hashingReader struct {
	r io.Reader
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
	n int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
	}
	return n, err
}

// upload submits a file (raw body with Content-Length) and returns the
// data id and the sha256 of what was sent. A full queue (503) is retried
// with backoff until ctx ends.
func (m *MetaDefender) upload(ctx context.Context, f File) (string, string, error) {
	backoff := durOr(m.BusyBackoff, time.Second)
	for {
		id, sent, retryAfter, err := m.uploadOnce(ctx, f)
		if err != nil || id != "" {
			return id, sent, err
		}
		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return "", "", fmt.Errorf("upload %s: MetaDefender stayed busy (scan queue full): %w", f.Name, ctx.Err())
		case <-t.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// uploadOnce returns an id, or retryAfter >= 0 with no id and no error when
// the server is busy.
func (m *MetaDefender) uploadOnce(ctx context.Context, f File) (id, sent string, retryAfter time.Duration, err error) {
	if f.Open == nil {
		return "", "", 0, fmt.Errorf("upload %s: content is not available", f.Name)
	}
	rc, err := f.Open(ctx)
	if err != nil {
		return "", "", 0, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer rc.Close()
	hr := &hashingReader{r: rc, h: sha256.New()}
	var body io.Reader = hr
	if f.Size == 0 {
		body = http.NoBody
	}
	req, err := m.newRequest(ctx, http.MethodPost, "/file", body)
	if err != nil {
		return "", "", 0, err
	}
	req.ContentLength = f.Size
	req.Header.Set("Content-Type", "application/octet-stream")
	if f.Name != "" {
		req.Header.Set("filename", encodeHeader(f.Name))
	}
	if m.Rule != "" {
		req.Header.Set("rule", encodeHeader(m.Rule))
	}
	resp, err := m.client().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", "", 0, ctx.Err()
		}
		return "", "", 0, fmt.Errorf("upload %s to MetaDefender: %w", f.Name, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		ra := time.Duration(0)
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			ra = min(time.Duration(s)*time.Second, time.Minute)
		}
		return "", "", ra, nil
	default:
		return "", "", 0, mdError("upload "+f.Name, resp)
	}
	if hr.n != f.Size {
		return "", "", 0, fmt.Errorf("upload %s: sent %d of %d bytes", f.Name, hr.n, f.Size)
	}
	var r struct {
		DataID string `json:"data_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil || r.DataID == "" {
		return "", "", 0, fmt.Errorf("upload %s: MetaDefender returned no data_id", f.Name)
	}
	return r.DataID, hex.EncodeToString(hr.h.Sum(nil)), 0, nil
}

// poll waits for an analysis to finish. When ctx's deadline passes the
// analysis is cancelled (it is retried later).
func (m *MetaDefender) poll(ctx context.Context, id string, f File) (*mdResult, error) {
	wait := durOr(m.PollMin, 250*time.Millisecond)
	maxWait := durOr(m.PollMax, 2*time.Second)
	failures := 0
	for {
		r, err := m.fetch(ctx, id)
		switch {
		case err == nil && r.done():
			if r.DataID != "" && r.DataID != id {
				return nil, fmt.Errorf("MetaDefender returned the analysis %s for %s", r.DataID, id)
			}
			return r, nil
		case err == nil:
			failures = 0
		case ctx.Err() != nil:
		case errors.Is(err, errMDNotFound):
			return nil, fmt.Errorf("MetaDefender lost the analysis of %s (%s)", f.Name, id)
		default:
			failures++
			if failures >= 5 {
				return nil, err
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				m.cancel(id)
			}
			progress := ""
			if r != nil {
				progress = fmt.Sprintf(" (%d%% done)", max(r.ProcessInfo.ProgressPercentage, r.ScanResults.ProgressPercentage))
			}
			return nil, fmt.Errorf("MetaDefender did not finish analysing %s%s: %w", f.Name, progress, ctx.Err())
		case <-t.C:
		}
		if wait *= 2; wait > maxWait {
			wait = maxWait
		}
	}
}

var errMDNotFound = errors.New("not found")

func (m *MetaDefender) fetch(ctx context.Context, id string) (*mdResult, error) {
	// size=1: child file lists are not needed (blocked-leaves names them).
	req, err := m.newRequest(ctx, http.MethodGet, "/file/"+url.PathEscape(id)+"?size=1", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch MetaDefender result: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errMDNotFound
	default:
		return nil, mdError("fetch result "+id, resp)
	}
	var r mdResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("fetch result %s: invalid JSON: %w", id, err)
	}
	if r.ProcessInfo.Result == "" && r.ScanResults.ScanAllResultI == nil {
		// {"<id>": "Not Found"}
		return nil, errMDNotFound
	}
	return &r, nil
}

// cancel asks MetaDefender to stop an analysis (best effort).
func (m *MetaDefender) cancel(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := m.newRequest(ctx, http.MethodPost, "/file/"+url.PathEscape(id)+"/cancel", nil)
	if err != nil {
		return
	}
	if resp, err := m.client().Do(req); err == nil {
		resp.Body.Close()
	}
}

// withLeaves names the blocked files inside an archive (best effort: the
// archive's own finding is kept when they cannot be listed).
func (m *MetaDefender) withLeaves(ctx context.Context, r *mdResult, f File, parent []Finding) []Finding {
	req, err := m.newRequest(ctx, http.MethodGet, "/file/"+url.PathEscape(r.DataID)+"/blocked-leaves", nil)
	if err != nil {
		return parent
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return parent
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return parent
	}
	var bl mdBlockedLeaves
	if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&bl) != nil {
		return parent
	}
	// The file itself is not a leaf inside it.
	kept := bl.Details[:0]
	for _, d := range bl.Details {
		if d.DataID != "" && d.DataID == r.DataID {
			continue
		}
		if d.DataID == "" && d.Path == "" {
			continue
		}
		kept = append(kept, d)
	}
	bl.Details = kept
	return leafFindings(&bl, f, parent, m.WebURL)
}

// Version reports the MetaDefender Core version.
func (m *MetaDefender) Version(ctx context.Context) (string, string, error) {
	req, err := m.newRequest(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return "", "", fmt.Errorf("MetaDefender version: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", mdError("version", resp)
	}
	var v struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil || v.Version == "" {
		return "", "", errors.New("MetaDefender version: unexpected response")
	}
	return v.Version, "", nil
}

// MDHealth is the result of a MetaDefender connection check.
type MDHealth struct {
	Version string
	// Rules available to the API key, with their maximum file sizes.
	Rules map[string]int64
}

// Check verifies that MetaDefender is ready (database and licence), the
// API key is accepted and the configured rule exists.
func (m *MetaDefender) Check(ctx context.Context) (*MDHealth, error) {
	if m.URL == "" {
		return nil, errors.New("metadefender.url is not set")
	}
	req, err := m.newRequest(ctx, http.MethodGet, "/readyz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("MetaDefender is not reachable: %w", err)
	}
	var ready struct {
		Database struct {
			Status *bool `json:"status"`
		} `json:"database"`
		License struct {
			Status string `json:"status"`
		} `json:"license"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	_ = json.Unmarshal(b, &ready)
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		msg := "MetaDefender is not ready"
		if ready.License.Status != "" && ready.License.Status != "ok" {
			msg += " (licence " + ready.License.Status + ")"
		} else if ready.Database.Status != nil && !*ready.Database.Status {
			msg += " (database unavailable)"
		}
		return nil, errors.New(msg)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("MetaDefender readiness check answered %d", resp.StatusCode)
	}
	if ready.License.Status != "" && ready.License.Status != "ok" {
		return nil, fmt.Errorf("MetaDefender licence is %s", ready.License.Status)
	}
	v, _, err := m.Version(ctx)
	if err != nil {
		return nil, err
	}
	h := &MDHealth{Version: v, Rules: map[string]int64{}}
	req, err = m.newRequest(ctx, http.MethodGet, "/file/rules", nil)
	if err != nil {
		return nil, err
	}
	resp, err = m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("MetaDefender rules: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, mdError("rules", resp)
	}
	var rules []struct {
		Name        string `json:"name"`
		MaxFileSize int64  `json:"max_file_size"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rules); err != nil {
		return nil, errors.New("MetaDefender rules: unexpected response")
	}
	for _, r := range rules {
		h.Rules[r.Name] = r.MaxFileSize
	}
	if m.Rule != "" {
		if _, ok := h.Rules[m.Rule]; !ok {
			names := make([]string, 0, len(rules))
			for _, r := range rules {
				names = append(names, r.Name)
			}
			return h, fmt.Errorf("rule %q is not available to this API key (available: %s)", m.Rule, strings.Join(names, ", "))
		}
	}
	return h, nil
}

// encodeHeader URL-encodes a header value (MetaDefender decodes rule names
// and file names as UTF-8); "+" and spaces are percent-encoded so either
// decoding style reads them back.
func encodeHeader(v string) string {
	safe := true
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0) {
			safe = false
			break
		}
	}
	if safe {
		return v
	}
	return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
}
