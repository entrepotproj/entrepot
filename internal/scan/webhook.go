package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/scan/drivers"
	"github.com/entrepotproj/entrepot/internal/store"
)

// SignatureHeader carries the HMAC-SHA256 of webhook request bodies:
// "sha256=" + hex(hmac(secret, body)).
const SignatureHeader = "X-Entrepot-Signature"

// JobTokenPrefix starts per-job webhook tokens.
const JobTokenPrefix = "esj_"

var (
	// ErrInvalidToken: the job does not exist, is not waiting for a
	// callback, or the token does not match.
	ErrInvalidToken = errors.New("invalid or expired scan job token")
	// ErrBadCallback: the callback body could not be interpreted.
	ErrBadCallback = errors.New("invalid scan callback")
)

// Sign returns the X-Entrepot-Signature value for body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// WebhookComponent describes the component in a scan request.
type WebhookComponent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Format  string `json:"format"`
	PURL    string `json:"purl,omitempty"`
	// Image and Digest are set for Docker images.
	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// WebhookRequest is POSTed to webhook scanners.
type WebhookRequest struct {
	Type       string            `json:"type"` // "scan" or "ping"
	JobID      string            `json:"jobId,omitempty"`
	Scanner    string            `json:"scanner"`
	Repository string            `json:"repository,omitempty"`
	Component  *WebhookComponent `json:"component,omitempty"`
	// Target is what to scan: "package" (purl; the artifact is the package
	// file) or "image" (the artifact is an OCI image layout tar).
	Target      string     `json:"target,omitempty"`
	ArtifactURL string     `json:"artifactUrl,omitempty"`
	CallbackURL string     `json:"callbackUrl,omitempty"`
	Token       string     `json:"token,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

func (s *Service) postWebhook(ctx context.Context, w *WebhookSettings, req *WebhookRequest) (int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", "Entrepot-Scanner")
	hr.Header.Set("X-Entrepot-Event", req.Type)
	if w.Secret != "" {
		hr.Header.Set(SignatureHeader, Sign(w.Secret, body))
	}
	resp, err := s.HTTP.Do(hr)
	if err != nil {
		return 0, fmt.Errorf("webhook %s: %w", redactURL(w.URL), err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("webhook %s answered %d: %s", redactURL(w.URL), resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp.StatusCode, nil
}

func redactURL(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		if j := strings.Index(u, "://"); j >= 0 && j < i {
			u = u[:j+3] + u[i+1:]
		}
	}
	return u
}

// dispatchWebhook hands a job to a webhook scanner. The job stays running
// (held by "webhook") until the scanner calls back or the deadline passes.
func (s *Service) dispatchWebhook(ctx context.Context, worker string, job *store.ScanJob, ls *loadedScanner,
	rp *repo.Repository, comp *store.Component, tg *target) {
	w := ls.Cfg.Webhook
	owner := store.JobOwner{Worker: worker}
	if w == nil || w.URL == "" {
		s.fail(ctx, job, owner, tg.description, errors.New("webhook scanner has no url"))
		return
	}
	base := strings.TrimRight(s.URLs.Base, "/")
	if base == "" {
		s.fail(ctx, job, owner, tg.description, errors.New("server.baseURL must be configured for webhook scanners"))
		return
	}
	var rnd [24]byte
	_, _ = rand.Read(rnd[:])
	token := JobTokenPrefix + hex.EncodeToString(rnd[:])
	hash := hashToken(token)
	deadline := w.CallbackTimeout()
	// Store the token before calling out, so a fast callback finds it.
	ok, err := s.Store.AwaitScanCallback(ctx, job.ID, worker, hash, deadline)
	if err != nil || !ok {
		s.Logger.Warn("hand job to webhook", "job", job.ID, "err", err)
		return
	}
	exp := time.Now().Add(deadline).UTC()
	req := &WebhookRequest{
		Type: "scan", JobID: job.ID, Scanner: ls.Name, Repository: rp.Name, Target: tg.kind,
		Component: &WebhookComponent{ID: comp.ID, Name: comp.Name, Version: comp.Version, Format: comp.Format,
			PURL: tg.purl, Image: tg.image, Digest: tg.digest},
		ArtifactURL: base + "/api/v1/scan-jobs/" + job.ID + "/artifact?token=" + token,
		CallbackURL: base + "/api/v1/scan-jobs/" + job.ID + "/result",
		Token:       token, ExpiresAt: &exp,
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := s.postWebhook(pctx, w, req); err != nil {
		s.Logger.Warn("webhook scan request failed", "job", job.ID, "scanner", ls.Name, "err", err)
		s.fail(ctx, job, store.JobOwner{TokenHash: hash}, tg.description, err)
		return
	}
	s.Logger.Info("scan handed to webhook", "job", job.ID, "scanner", ls.Name, "target", tg.description)
}

// JobForToken returns the running webhook job id authenticated by token.
func (s *Service) JobForToken(ctx context.Context, id, token string) (*store.ScanJob, error) {
	if !strings.HasPrefix(token, JobTokenPrefix) {
		return nil, ErrInvalidToken
	}
	j, err := s.Store.ScanJobByToken(ctx, id, hashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalid) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	return j, nil
}

// ServeArtifact streams what a webhook scanner should scan: the package
// file, or an OCI image layout tar for Docker images. The quarantine gate
// does not apply.
func (s *Service) ServeArtifact(w http.ResponseWriter, r *http.Request, job *store.ScanJob) error {
	ctx := r.Context()
	comp, err := s.Store.GetComponent(ctx, job.ComponentID)
	if err != nil {
		return err
	}
	rp, err := s.Repos.GetByID(ctx, comp.RepositoryID)
	if err != nil {
		return err
	}
	if comp.Format == "docker" {
		tg, err := s.resolveTarget(ctx, rp, comp)
		if err != nil {
			return err
		}
		exp, err := s.imageExporter()
		if err != nil {
			return err
		}
		dir, err := s.workDir(job.ID)
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		var digests []string
		if len(tg.platforms) == 1 && tg.platforms[0].Platform == "" {
			digests = []string{tg.digest}
		} else {
			for _, m := range tg.platforms {
				digests = append(digests, m.Digest)
			}
		}
		layout := filepath.Join(dir, "layout")
		if err := exp.ExportImages(ctx, rp, comp.Name, digests, layout); err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeName(comp.Name+"-"+comp.Version)+`.oci.tar"`)
		w.WriteHeader(http.StatusOK)
		return WriteTar(w, layout)
	}
	assets, err := s.Store.ListComponentAssets(ctx, comp.ID)
	if err != nil {
		return err
	}
	a := primaryAsset(assets)
	if a == nil {
		return store.ErrNotFound
	}
	rc, err := s.Repos.Open(ctx, rp, a)
	if err != nil {
		return err
	}
	defer rc.Close()
	name := a.Path
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeName(name)+`"`)
	w.Header().Set("X-Checksum-Sha256", strings.TrimPrefix(a.Digest, "sha256:"))
	http.ServeContent(w, r, "", a.UpdatedAt, rc)
	return nil
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '/' || r == '\\' || r < 32 {
			return '_'
		}
		return r
	}, s)
}

// primaryAsset picks the package file of a component (not metadata).
func primaryAsset(as []*store.Asset) *store.Asset {
	var best *store.Asset
	for _, a := range as {
		if strings.HasSuffix(a.Path, ".metadata") || strings.HasSuffix(a.Path, ".asc") || strings.HasSuffix(a.Path, ".sig") {
			continue
		}
		if best == nil || a.Size > best.Size {
			best = a
		}
	}
	if best == nil && len(as) > 0 {
		best = as[0]
	}
	return best
}

// WriteTar writes the files under dir to w as a tar archive.
func WriteTar(w io.Writer, dir string) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// Callback is a webhook scanner's report.
type Callback struct {
	// Format is entrepot (Findings), sarif or cyclonedx (Document).
	Format      string
	Findings    []drivers.Finding
	Document    json.RawMessage
	Error       string
	Unsupported bool
	// Scanner/DB versions, optional.
	ScannerVersion string
}

// SubmitCallback completes a webhook job with the scanner's report.
func (s *Service) SubmitCallback(ctx context.Context, job *store.ScanJob, token string, cb *Callback) error {
	owner := store.JobOwner{TokenHash: hashToken(token)}
	if cb.Error != "" {
		s.fail(ctx, job, owner, "", errors.New("scanner reported: "+cb.Error))
		return nil
	}
	tgDesc := ""
	if comp, err := s.Store.GetComponent(ctx, job.ComponentID); err == nil {
		if rp, err := s.Repos.GetByID(ctx, comp.RepositoryID); err == nil {
			if tg, err := s.resolveTarget(ctx, rp, comp); err == nil {
				tgDesc = tg.description
			}
		}
	}
	sm := summary{Target: tgDesc, ScannerVersion: cb.ScannerVersion, Attempt: job.Attempts}
	if cb.Unsupported {
		s.complete(ctx, job, owner, &store.ScanResult{Status: "unsupported", Summary: sm.json()})
		return nil
	}
	var fs []drivers.Finding
	var err error
	switch strings.ToLower(cb.Format) {
	case "", "entrepot":
		if cb.Findings == nil && len(cb.Document) > 0 {
			return fmt.Errorf("%w: format is required with a document (sarif or cyclonedx)", ErrBadCallback)
		}
		fs = drivers.Dedupe(cb.Findings)
	case "sarif":
		fs, err = drivers.ParseSARIF(cb.Document)
	case "cyclonedx":
		fs, err = drivers.ParseCycloneDX(cb.Document)
	default:
		return fmt.Errorf("%w: unknown format %q", ErrBadCallback, cb.Format)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadCallback, err)
	}
	sm.Counts = countFindings(fs)
	if comp, err := s.Store.GetComponent(ctx, job.ComponentID); err == nil && comp.Format == "docker" {
		if a, err := s.Store.GetAsset(ctx, comp.RepositoryID, comp.Name+"/_tags/"+comp.Version); err == nil {
			sm.Digest, sm.Digests = a.Digest, []string{a.Digest}
		}
	}
	res := &store.ScanResult{Status: "ok", Summary: sm.json(), Findings: toStoreFindings(fs)}
	if _, err := s.Store.CompleteScanJob(ctx, job.ID, owner, res); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		return err
	}
	s.afterResult(ctx, job.ComponentID, res)
	return nil
}

// TestResult reports a scanner check.
type TestResult struct {
	OK      bool
	Message string
	Version string
}

// TestScanner checks that a scanner works: the CLI runs (version), or the
// webhook accepts a signed ping.
func (s *Service) TestScanner(ctx context.Context, sc *store.Scanner) TestResult {
	ls, err := s.loadScanner(sc)
	if err != nil {
		return TestResult{Message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	switch ls.Type {
	case TypeWebhook:
		w := ls.Cfg.Webhook
		if w == nil || w.URL == "" {
			return TestResult{Message: "webhook.url is not set"}
		}
		code, err := s.postWebhook(ctx, w, &WebhookRequest{Type: "ping", Scanner: ls.Name})
		if err != nil {
			return TestResult{Message: err.Error()}
		}
		return TestResult{OK: true, Message: fmt.Sprintf("webhook answered %d", code)}
	default:
		dir, err := s.workDir("test0000")
		if err != nil {
			return TestResult{Message: err.Error()}
		}
		defer os.RemoveAll(dir)
		v, db, err := s.driver(ls, dir).Version(ctx)
		if err != nil {
			return TestResult{Message: err.Error()}
		}
		msg := ls.Type + " " + v
		if db != "" {
			msg += ", vulnerability DB " + db
		}
		if t := ls.Cfg.Trivy; ls.Type == TypeTrivy && t != nil && t.ServerURL != "" {
			if err := s.checkTrivyServer(ctx, t.ServerURL); err != nil {
				return TestResult{Message: msg + "; server: " + err.Error(), Version: v}
			}
			msg += "; server " + t.ServerURL + " is healthy"
		}
		return TestResult{OK: true, Message: msg, Version: v}
	}
}

func (s *Service) checkTrivyServer(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz answered %d", resp.StatusCode)
	}
	return nil
}
