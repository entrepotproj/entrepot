package api

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// usageWindow maps a range to its source table and bucket size.
type usageWindow struct {
	name   string
	length time.Duration
	stride time.Duration
	hourly bool
}

func windowFor(rng string) usageWindow {
	switch rng {
	case "1h":
		return usageWindow{"1h", time.Hour, time.Minute, false}
	case "7d":
		return usageWindow{"7d", 7 * 24 * time.Hour, 3 * time.Hour, true}
	case "30d":
		return usageWindow{"30d", 30 * 24 * time.Hour, 12 * time.Hour, true}
	default:
		return usageWindow{"24h", 24 * time.Hour, 15 * time.Minute, false}
	}
}

// from aligns the window start to the stride (date_bin origin).
func (w usageWindow) from(now time.Time) time.Time {
	return now.Add(-w.length).Truncate(w.stride).Add(w.stride)
}

// readableRepoIDs returns the repositories the caller can read; nil with
// all=true for administrators.
func (s *Server) readableRepoIDs(r *http.Request) (ids []string, all bool, err error) {
	ctx := r.Context()
	p := principal(r)
	if s.Authz.IsAdmin(ctx, p) {
		return nil, true, nil
	}
	rs, err := s.Store.ListRepositories(ctx)
	if err != nil {
		return nil, false, err
	}
	ids = []string{}
	for _, x := range rs {
		if s.Authz.Can(ctx, p, authz.Read, authz.Target{Name: x.Name, AnonymousRead: x.AnonymousRead}) {
			ids = append(ids, x.ID)
		}
	}
	return ids, false, nil
}

func usageCountsToAPI(c store.UsageCounts) apigen.UsageCounts {
	return apigen.UsageCounts{
		Requests: c.Requests, Errors: c.Errors, Downloads: c.Downloads, Uploads: c.Uploads,
		BytesOut: c.BytesOut, BytesIn: c.BytesIn, CacheHits: c.CacheHits, CacheMisses: c.CacheMisses,
	}
}

// series returns a gap-filled series for the window.
func (s *Server) series(r *http.Request, ids []string, w usageWindow, from time.Time) ([]apigen.UsagePoint, error) {
	pts, err := s.Store.UsageSeries(r.Context(), ids, from, w.stride, w.hourly)
	if err != nil {
		return nil, err
	}
	byT := map[int64]store.UsagePoint{}
	for _, p := range pts {
		byT[p.T.Unix()] = p
	}
	out := []apigen.UsagePoint{}
	for t := from; !t.After(time.Now()); t = t.Add(w.stride) {
		p := byT[t.Unix()]
		out = append(out, apigen.UsagePoint{T: t, Requests: p.Requests, Errors: p.Errors, Downloads: p.Downloads,
			Uploads: p.Uploads, BytesOut: p.BytesOut, BytesIn: p.BytesIn})
	}
	return out, nil
}

func (s *Server) requestRate(r *http.Request, ids []string) float32 {
	c, err := s.Store.UsageTotals(r.Context(), ids, time.Now().Add(-5*time.Minute).Truncate(time.Minute), false)
	if err != nil {
		return 0
	}
	return float32(c.Requests) / 300
}

func (s *Server) GetMetricsOverview(w http.ResponseWriter, r *http.Request, params apigen.GetMetricsOverviewParams) {
	ctx := r.Context()
	win := windowFor(string(deref(params.Range)))
	from := win.from(time.Now().UTC())
	ids, all, err := s.readableRepoIDs(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := apigen.UsageOverview{
		Range: win.name, From: from, BucketSeconds: int(win.stride.Seconds()), Scope: apigen.Readable,
		TopRepositories: []apigen.RepositoryUsage{}, Inventory: []apigen.FormatInventory{}, Scan: map[string]int64{},
	}
	if all {
		out.Scope = apigen.All
	}
	if ids != nil && len(ids) == 0 {
		// Nothing readable: empty dashboard rather than an error.
		out.Series, _ = s.series(r, []string{"00000000-0000-0000-0000-000000000000"}, win, from)
		httpx.WriteJSON(w, http.StatusOK, out)
		return
	}
	tot, err := s.Store.UsageTotals(ctx, ids, from, win.hourly)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out.Totals = usageCountsToAPI(tot)
	out.RequestRate = s.requestRate(r, ids)
	if out.Series, err = s.series(r, ids, win, from); err != nil {
		s.writeErr(w, err)
		return
	}
	top, err := s.Store.UsageByRepository(ctx, ids, from, win.hourly, 10)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	for _, t := range top {
		out.TopRepositories = append(out.TopRepositories, apigen.RepositoryUsage{
			Repository: t.Repository, Format: t.Format, Kind: t.Kind, Counts: usageCountsToAPI(t.UsageCounts)})
	}
	inv, err := s.Store.Inventory(ctx, ids)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	for _, f := range inv {
		out.Inventory = append(out.Inventory, apigen.FormatInventory{Format: f.Format, Repositories: f.Repositories,
			Components: f.Components, Assets: f.Assets, TotalBytes: f.TotalBytes})
	}
	if out.Scan, err = s.Store.ScanSummary(ctx, ids); err != nil {
		s.writeErr(w, err)
		return
	}
	if all {
		stores, err := s.Store.ListBlobStores(ctx)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		list := []apigen.BlobStoreSummary{}
		for _, b := range stores {
			u, err := s.Store.BlobStoreUsage(ctx, b.ID)
			if err != nil {
				continue
			}
			list = append(list, apigen.BlobStoreSummary{Name: b.Name, Type: b.Type, BlobCount: u.BlobCount,
				TotalBytes: u.TotalBytes, Repositories: u.Repositories})
		}
		out.Storage = &list
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) GetRepositoryMetrics(w http.ResponseWriter, r *http.Request, name string, params apigen.GetRepositoryMetricsParams) {
	rp, ok := s.requireRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	win := windowFor(string(deref(params.Range)))
	from := win.from(time.Now().UTC())
	ids := []string{rp.ID}
	tot, err := s.Store.UsageTotals(r.Context(), ids, from, win.hourly)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	series, err := s.series(r, ids, win, from)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, apigen.RepositoryUsageReport{
		Repository: rp.Name, Range: win.name, From: from, BucketSeconds: int(win.stride.Seconds()),
		Totals: usageCountsToAPI(tot), RequestRate: s.requestRate(r, ids), Series: series,
	})
}

func (s *Server) ListActivity(w http.ResponseWriter, r *http.Request, params apigen.ListActivityParams) {
	q := store.ActivityQuery{
		Actor: deref(params.Actor), Path: deref(params.Path), From: params.From, To: params.To,
		BeforeID: deref(params.Before), Limit: deref(params.Limit),
	}
	if params.Kind != nil {
		q.Kind = string(*params.Kind)
	}
	if repoName := deref(params.Repository); repoName != "" {
		rp, ok := s.requireRepo(w, r, repoName, authz.Admin)
		if !ok {
			return
		}
		q.RepositoryIDs = []string{rp.ID}
	} else if !s.requireAdmin(w, r) {
		return
	}
	csvOut := params.Format != nil && *params.Format == "csv"
	if csvOut && q.Limit == 0 {
		q.Limit = 1000
	}
	evs, err := s.Store.ListActivity(r.Context(), q)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if csvOut {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="entrepot-activity.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "at", "repository", "format", "kind", "path", "component", "actor", "actor_kind", "remote_ip", "user_agent", "bytes"})
		for _, e := range evs {
			_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.At.Format(time.RFC3339), e.Repository, e.Format, e.Kind,
				e.Path, e.Component, e.Actor, e.ActorKind, e.RemoteIP, e.UserAgent, strconv.FormatInt(e.Bytes, 10)})
		}
		cw.Flush()
		return
	}
	out := make([]apigen.ActivityEvent, 0, len(evs))
	for _, e := range evs {
		ae := apigen.ActivityEvent{
			Id: e.ID, At: e.At, Repository: e.Repository, Format: e.Format, Kind: apigen.ActivityEventKind(e.Kind),
			Path: e.Path, ComponentId: e.ComponentID, Actor: e.Actor, ActorKind: e.ActorKind, RemoteIp: e.RemoteIP,
			UserAgent: e.UserAgent, Bytes: e.Bytes,
		}
		if e.Component != "" {
			ae.Component = ptr(e.Component)
		}
		out = append(out, ae)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
