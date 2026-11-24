package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/entrepotproj/entrepot/internal/api/apigen"
	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/scan"
	"github.com/entrepotproj/entrepot/internal/scan/drivers"
	"github.com/entrepotproj/entrepot/internal/store"
)

// ---- scanners ---------------------------------------------------------------

func scannerToAPI(sc *store.Scanner) apigen.Scanner {
	out := apigen.Scanner{Name: sc.Name, Type: apigen.ScannerType(sc.Type), Enabled: sc.Enabled,
		CreatedAt: sc.CreatedAt, UpdatedAt: sc.UpdatedAt}
	cfg, err := scan.ParseScannerConfig(sc.Config)
	if err != nil {
		return out
	}
	out.RescanIntervalHours = cfg.RescanIntervalHours
	// Secrets (serverToken, webhook secret) are write-only.
	if t := cfg.Trivy; t != nil {
		out.Trivy = &apigen.TrivySettings{Binary: optStr(t.Binary), ServerUrl: optStr(t.ServerURL),
			TimeoutSeconds: optInt(t.TimeoutSeconds), ExtraArgs: optSlice(t.ExtraArgs)}
	}
	if g := cfg.Grype; g != nil {
		out.Grype = &apigen.GrypeSettings{Binary: optStr(g.Binary), TimeoutSeconds: optInt(g.TimeoutSeconds),
			ExtraArgs: optSlice(g.ExtraArgs)}
	}
	if w := cfg.Webhook; w != nil {
		out.Webhook = &apigen.WebhookScannerSettings{Url: w.URL, TimeoutSeconds: optInt(w.TimeoutSeconds)}
	}
	return out
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

func optSlice(s []string) *[]string {
	if len(s) == 0 {
		return nil
	}
	return &s
}

// scannerConfig validates a scanner request; secrets omitted on update keep
// their stored (sealed) value.
func (s *Server) scannerConfig(in apigen.ScannerInput, prev *store.Scanner) (*store.Scanner, error) {
	if !nameRE.MatchString(in.Name) {
		return nil, errBad("invalid name: use lowercase letters, digits, '.', '_' and '-'")
	}
	cfg := &scan.ScannerConfig{RescanIntervalHours: deref(in.RescanIntervalHours)}
	if cfg.RescanIntervalHours < 0 || cfg.RescanIntervalHours > 24*365 {
		return nil, errBad("rescanIntervalHours must be between 0 and 8760")
	}
	var old *scan.ScannerConfig
	if prev != nil {
		old, _ = scan.ParseScannerConfig(prev.Config)
	}
	checkTimeout := func(t *int) error {
		if t != nil && (*t < 0 || *t > 24*3600) {
			return errBad("timeoutSeconds must be between 0 and 86400")
		}
		return nil
	}
	switch in.Type {
	case scan.TypeTrivy:
		t := &scan.TrivySettings{}
		if in.Trivy != nil {
			if err := checkTimeout(in.Trivy.TimeoutSeconds); err != nil {
				return nil, err
			}
			t = &scan.TrivySettings{Binary: deref(in.Trivy.Binary), ServerURL: strings.TrimRight(deref(in.Trivy.ServerUrl), "/"),
				ServerToken: deref(in.Trivy.ServerToken), TimeoutSeconds: deref(in.Trivy.TimeoutSeconds), ExtraArgs: deref(in.Trivy.ExtraArgs)}
		}
		if t.ServerURL != "" && !isHTTPURL(t.ServerURL) {
			return nil, errBad("trivy.serverUrl must be an http(s) URL")
		}
		if t.ServerToken == "" && t.ServerURL != "" && old != nil && old.Trivy != nil && old.Trivy.ServerURL == t.ServerURL {
			t.ServerToken = old.Trivy.ServerToken
		}
		cfg.Trivy = t
	case scan.TypeGrype:
		g := &scan.GrypeSettings{}
		if in.Grype != nil {
			if err := checkTimeout(in.Grype.TimeoutSeconds); err != nil {
				return nil, err
			}
			g = &scan.GrypeSettings{Binary: deref(in.Grype.Binary), TimeoutSeconds: deref(in.Grype.TimeoutSeconds),
				ExtraArgs: deref(in.Grype.ExtraArgs)}
		}
		cfg.Grype = g
	case scan.TypeWebhook:
		if in.Webhook == nil || !isHTTPURL(in.Webhook.Url) {
			return nil, errBad("webhook.url (an http(s) URL) is required for webhook scanners")
		}
		if err := checkTimeout(in.Webhook.TimeoutSeconds); err != nil {
			return nil, err
		}
		w := &scan.WebhookSettings{URL: in.Webhook.Url, Secret: deref(in.Webhook.Secret), TimeoutSeconds: deref(in.Webhook.TimeoutSeconds)}
		if w.Secret == "" && old != nil && old.Webhook != nil {
			w.Secret = old.Webhook.Secret
		}
		cfg.Webhook = w
	default:
		return nil, errBad("type must be trivy, grype or webhook")
	}
	if err := cfg.Seal(s.Secrets); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return &store.Scanner{Name: in.Name, Type: string(in.Type), Config: raw, Enabled: enabled}, nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (s *Server) ListScanners(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	scs, err := s.Store.ListScanners(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.Scanner, 0, len(scs))
	for _, sc := range scs {
		out = append(out, scannerToAPI(sc))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateScanner(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.ScannerInput
	if !decode(w, r, &in) {
		return
	}
	sc, err := s.scannerConfig(in, nil)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out, err := s.Store.CreateScanner(r.Context(), sc)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "scanner.create", out.Name, map[string]any{"type": out.Type, "enabled": out.Enabled})
	httpx.WriteJSON(w, http.StatusCreated, scannerToAPI(out))
}

func (s *Server) GetScanner(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	sc, err := s.Store.GetScanner(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, scannerToAPI(sc))
}

func (s *Server) UpdateScanner(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.ScannerInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		in.Name = name
	}
	if in.Name != name {
		s.writeErr(w, errBad("scanners cannot be renamed"))
		return
	}
	prev, err := s.Store.GetScanner(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	sc, err := s.scannerConfig(in, prev)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out, err := s.Store.UpdateScanner(r.Context(), sc)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "scanner.update", out.Name, map[string]any{"type": out.Type, "enabled": out.Enabled})
	httpx.WriteJSON(w, http.StatusOK, scannerToAPI(out))
}

// DeleteScanner refuses (409) while a repository's scan settings use the
// scanner; remove it from those repositories first.
func (s *Server) DeleteScanner(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	if _, err := s.Store.GetScanner(ctx, name); err != nil {
		s.writeErr(w, err)
		return
	}
	repos, err := s.Store.ListRepositories(ctx)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var users []string
	for _, rr := range repos {
		rp, err := s.Repos.Get(ctx, rr.Name)
		if err != nil || rp.Cfg.Scan == nil {
			continue
		}
		for _, n := range rp.Cfg.Scan.Scanners {
			if n == name {
				users = append(users, rp.Name)
			}
		}
	}
	if len(users) > 0 {
		httpx.WriteError(w, http.StatusConflict, "in_use",
			"scanner "+name+" is used by repositories "+strings.Join(users, ", ")+"; remove it from their scan settings first")
		return
	}
	if err := s.Store.DeleteScanner(ctx, name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "scanner.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) TestScanner(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	sc, err := s.Store.GetScanner(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	res := s.Scan.TestScanner(r.Context(), sc)
	out := apigen.ScannerTestResult{Ok: res.OK, Message: res.Message}
	if res.Version != "" {
		out.Version = &res.Version
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---- jobs & results ----------------------------------------------------------

func jobToAPI(j *store.ScanJob) apigen.ScanJob {
	out := apigen.ScanJob{
		Id: j.ID, ComponentId: j.ComponentID, Component: j.Component + "@" + j.Version, Repository: j.Repository,
		Scanner: j.Scanner, Status: apigen.ScanJobStatus(j.Status), Reason: apigen.ScanJobReason(j.Reason),
		Attempts: j.Attempts, Error: j.Error, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt, FinishedAt: j.FinishedAt,
	}
	if j.Status == "queued" {
		ra := j.RunAfter
		out.RunAfter = &ra
	}
	return out
}

func (s *Server) ScanComponent(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.componentWithRepo(w, r, id, authz.Write)
	if !ok {
		return
	}
	var in apigen.ScanRequest
	if r.ContentLength != 0 && r.Body != nil {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
			return
		}
	}
	ctx := r.Context()
	var names []string
	if in.Scanners != nil && len(*in.Scanners) > 0 {
		for _, n := range *in.Scanners {
			sc, err := s.Store.GetScanner(ctx, n)
			if err != nil {
				s.writeErr(w, errBad("unknown scanner "+n))
				return
			}
			if !sc.Enabled {
				s.writeErr(w, errBad("scanner "+n+" is disabled"))
				return
			}
			names = append(names, n)
		}
	} else {
		rp, err := s.Repos.Get(ctx, c.Repository)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		if rp.Cfg.Scan == nil || len(rp.Cfg.Scan.Scanners) == 0 {
			s.writeErr(w, errBad("repository "+rp.Name+" has no scanners configured; name the scanners to use"))
			return
		}
		names = rp.Cfg.Scan.Scanners
	}
	jobs, err := s.Scan.Enqueue(ctx, c.ID, names, "manual")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.ScanJob, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobToAPI(j))
	}
	s.audit(r, "component.scan", c.Repository+"/"+c.Name+"@"+c.Version, map[string]any{"scanners": names})
	httpx.WriteJSON(w, http.StatusAccepted, out)
}

func countsToAPI(c map[string]int) apigen.SeverityCounts {
	return apigen.SeverityCounts{Critical: c["critical"], High: c["high"], Medium: c["medium"], Low: c["low"], Unknown: c["unknown"]}
}

// maxListedFindings is how many findings a component lists in search results.
const maxListedFindings = 5

// attachFindings fills findingCounts and the most severe findings of each
// component (out[i] describes cs[i]). Findings covered by an active waiver are
// left out, and a vulnerability reported by several scanners counts once, as
// in the component's verdict.
func (s *Server) attachFindings(ctx context.Context, cs []*store.Component, out []apigen.Component) error {
	if len(cs) == 0 {
		return nil
	}
	ids := make([]string, len(cs))
	for i, c := range cs {
		ids[i] = c.ID
	}
	found, err := s.Store.LatestFindings(ctx, ids)
	if err != nil {
		return err
	}
	waivers, err := s.Store.ListWaivers(ctx, true)
	if err != nil {
		return err
	}
	for i, c := range cs {
		counts := map[string]int{}
		seen := map[string]bool{}
		var list []apigen.Finding
		for _, f := range found[c.ID] {
			if waived(waivers, c, f.VulnID) {
				continue
			}
			k := f.VulnID + "\x00" + f.Package + "\x00" + f.InstalledVersion
			if seen[k] {
				continue
			}
			seen[k] = true
			counts[f.Severity]++
			list = append(list, apigen.Finding{VulnId: f.VulnID, Severity: apigen.Severity(f.Severity), Package: f.Package,
				InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion, Title: f.Title, Url: f.URL})
		}
		sort.SliceStable(list, func(a, b int) bool {
			return drivers.SeverityRank(string(list[a].Severity)) > drivers.SeverityRank(string(list[b].Severity))
		})
		if len(list) > maxListedFindings {
			list = list[:maxListedFindings]
		}
		if list == nil {
			list = []apigen.Finding{}
		}
		out[i].FindingCounts = ptr(countsToAPI(counts))
		out[i].Findings = &list
	}
	return nil
}

func waived(waivers []*store.Waiver, c *store.Component, vuln string) bool {
	for _, w := range waivers {
		if scan.WaiverMatches(w, c.Repository, c.Name, c.Version, vuln) {
			return true
		}
	}
	return false
}

func (s *Server) GetComponentScans(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.componentWithRepo(w, r, id, authz.Read)
	if !ok {
		return
	}
	ctx := r.Context()
	v, err := s.Scan.ComponentVerdict(ctx, c)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	jobs, err := s.Store.ComponentScanJobs(ctx, c.ID, 20)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// The verdict is computed from the latest results, active waivers and the
	// repository's current policy (the stored copy may lag a settings change).
	out := apigen.ComponentScans{
		ScanState: apigen.ScanState(v.State), Quarantined: v.Quarantined, ScannedAt: v.ScannedAt,
		Results: []apigen.ScanResult{}, Jobs: make([]apigen.ScanJob, 0, len(jobs)),
	}
	if v.Reason != "" {
		out.QuarantineReason = &v.Reason
	}
	byScanner := map[string][]scan.Finding{}
	for _, f := range v.Findings {
		byScanner[f.Scanner] = append(byScanner[f.Scanner], f)
	}
	for _, res := range v.Results {
		var sm struct {
			Target string `json:"target"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal(res.Summary, &sm)
		ar := apigen.ScanResult{Id: res.ID, Scanner: res.Scanner, Status: apigen.ScanResultStatus(res.Status),
			ScannedAt: res.ScannedAt, Findings: []apigen.Finding{}}
		if sm.Target != "" {
			ar.Target = &sm.Target
		}
		if sm.Error != "" {
			ar.Error = &sm.Error
		}
		counts := map[string]int{}
		for _, f := range byScanner[res.Scanner] {
			af := apigen.Finding{VulnId: f.VulnID, Severity: apigen.Severity(f.Severity), Package: f.Package,
				InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion, Title: f.Title, Url: f.URL, Waived: f.Waived}
			if f.WaiverID != "" {
				af.WaiverId = ptr(f.WaiverID)
			} else {
				counts[f.Severity]++
			}
			ar.Findings = append(ar.Findings, af)
		}
		// Counts are of unwaived findings.
		ar.Counts = countsToAPI(counts)
		out.Results = append(out.Results, ar)
	}
	for _, j := range jobs {
		out.Jobs = append(out.Jobs, jobToAPI(j))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) ListScanJobs(w http.ResponseWriter, r *http.Request, params apigen.ListScanJobsParams) {
	if !s.requireAdmin(w, r) {
		return
	}
	status := ""
	if params.Status != nil {
		status = string(*params.Status)
	}
	jobs, err := s.Store.ListScanJobs(r.Context(), status, deref(params.Limit))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.ScanJob, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobToAPI(j))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// jobToken returns the per-job token from the query or a Bearer header.
func jobToken(r *http.Request, q *string) string {
	if q != nil && *q != "" {
		return *q
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return r.Header.Get("X-Entrepot-Job-Token")
}

func (s *Server) scanJobForToken(w http.ResponseWriter, r *http.Request, id, token string) (*store.ScanJob, bool) {
	job, err := s.Scan.JobForToken(r.Context(), id, token)
	if errors.Is(err, scan.ErrInvalidToken) {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return nil, false
	}
	if err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	return job, true
}

func (s *Server) GetScanJobArtifact(w http.ResponseWriter, r *http.Request, id string, params apigen.GetScanJobArtifactParams) {
	job, ok := s.scanJobForToken(w, r, id, jobToken(r, params.Token))
	if !ok {
		return
	}
	if err := s.Scan.ServeArtifact(w, r, job); err != nil {
		s.Logger.Warn("serve scan artifact", "job", id, "err", err)
		if w.Header().Get("Content-Type") == "" {
			s.writeErr(w, err)
		}
	}
}

func (s *Server) SubmitScanJobResult(w http.ResponseWriter, r *http.Request, id string, params apigen.SubmitScanJobResultParams) {
	token := jobToken(r, params.Token)
	job, ok := s.scanJobForToken(w, r, id, token)
	if !ok {
		return
	}
	// Scanners may send extra fields; decode leniently (documents can be large).
	var in struct {
		Format         string            `json:"format"`
		Findings       []json.RawMessage `json:"findings"`
		Document       json.RawMessage   `json:"document"`
		Error          string            `json:"error"`
		Unsupported    bool              `json:"unsupported"`
		ScannerVersion string            `json:"scannerVersion"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	cb := &scan.Callback{Format: in.Format, Document: in.Document, Error: in.Error, Unsupported: in.Unsupported,
		ScannerVersion: in.ScannerVersion}
	if in.Findings != nil {
		cb.Findings = []drivers.Finding{}
	}
	for i, raw := range in.Findings {
		var f drivers.Finding
		if err := json.Unmarshal(raw, &f); err != nil || f.VulnID == "" {
			httpx.WriteError(w, http.StatusBadRequest, "bad_request", "findings["+itoa(i)+"]: vulnId is required")
			return
		}
		cb.Findings = append(cb.Findings, f)
	}
	if len(cb.Document) > 0 && string(cb.Document) == "null" {
		cb.Document = nil
	}
	if err := s.Scan.SubmitCallback(r.Context(), job, token, cb); err != nil {
		switch {
		case errors.Is(err, scan.ErrBadCallback):
			httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		case errors.Is(err, scan.ErrInvalidToken):
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		default:
			s.writeErr(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// ---- waivers ----------------------------------------------------------------

func waiverToAPI(wv *store.Waiver) apigen.Waiver {
	return apigen.Waiver{Id: wv.ID, VulnId: wv.VulnID, RepositoryPattern: wv.RepositoryPattern,
		ComponentPattern: wv.ComponentPattern, Reason: wv.Reason, ExpiresAt: wv.ExpiresAt, CreatedBy: wv.CreatedBy,
		CreatedAt: wv.CreatedAt}
}

func waiverFromAPI(in apigen.WaiverInput) (*store.Waiver, error) {
	wv := &store.Waiver{VulnID: strings.TrimSpace(in.VulnId), RepositoryPattern: strings.TrimSpace(deref(in.RepositoryPattern)),
		ComponentPattern: strings.TrimSpace(deref(in.ComponentPattern)), Reason: deref(in.Reason), ExpiresAt: in.ExpiresAt}
	if wv.VulnID == "" {
		return nil, errBad("vulnId is required (use * for any vulnerability)")
	}
	if wv.RepositoryPattern == "" {
		wv.RepositoryPattern = "*"
	}
	if wv.ComponentPattern == "" {
		wv.ComponentPattern = "*"
	}
	if wv.VulnID == "*" && wv.ComponentPattern == "*" && wv.RepositoryPattern == "*" {
		return nil, errBad("a waiver for every vulnerability must be restricted to a repository or component pattern")
	}
	return wv, nil
}

func (s *Server) ListWaivers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ws, err := s.Store.ListWaivers(r.Context(), false)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.Waiver, 0, len(ws))
	for _, wv := range ws {
		out = append(out, waiverToAPI(wv))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateWaiver(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.WaiverInput
	if !decode(w, r, &in) {
		return
	}
	wv, err := waiverFromAPI(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	wv.CreatedBy = principal(r).Name
	out, err := s.Store.CreateWaiver(r.Context(), wv)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Scan.ReevaluateVulns(r.Context(), []string{out.VulnID})
	s.audit(r, "waiver.create", out.VulnID, waiverToAPI(out))
	httpx.WriteJSON(w, http.StatusCreated, waiverToAPI(out))
}

func (s *Server) GetWaiver(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	wv, err := s.Store.GetWaiver(r.Context(), id)
	if err != nil {
		s.writeErr(w, notFoundIfInvalid(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, waiverToAPI(wv))
}

func notFoundIfInvalid(err error) error {
	if errors.Is(err, store.ErrInvalid) {
		return store.ErrNotFound
	}
	return err
}

func (s *Server) UpdateWaiver(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.WaiverInput
	if !decode(w, r, &in) {
		return
	}
	prev, err := s.Store.GetWaiver(r.Context(), id)
	if err != nil {
		s.writeErr(w, notFoundIfInvalid(err))
		return
	}
	wv, err := waiverFromAPI(in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	wv.ID = id
	out, err := s.Store.UpdateWaiver(r.Context(), wv)
	if err != nil {
		s.writeErr(w, notFoundIfInvalid(err))
		return
	}
	s.Scan.ReevaluateVulns(r.Context(), []string{prev.VulnID, out.VulnID})
	s.audit(r, "waiver.update", out.VulnID, waiverToAPI(out))
	httpx.WriteJSON(w, http.StatusOK, waiverToAPI(out))
}

func (s *Server) DeleteWaiver(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	out, err := s.Store.DeleteWaiver(r.Context(), id)
	if err != nil {
		s.writeErr(w, notFoundIfInvalid(err))
		return
	}
	s.Scan.ReevaluateVulns(r.Context(), []string{out.VulnID})
	s.audit(r, "waiver.delete", out.VulnID, waiverToAPI(out))
	w.WriteHeader(http.StatusNoContent)
}
