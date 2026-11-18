package npm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

type searchObject struct {
	Package     map[string]any `json:"package"`
	Score       map[string]any `json:"score"`
	SearchScore float64        `json:"searchScore"`
}

type searchResult struct {
	Objects []searchObject `json:"objects"`
	Total   int            `json:"total"`
	Time    string         `json:"time"`
}

func (h *Handler) search(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	q := r.URL.Query()
	size, _ := strconv.Atoi(q.Get("size"))
	if size <= 0 || size > 250 {
		size = 20
	}
	from, _ := strconv.Atoi(q.Get("from"))
	if from < 0 {
		from = 0
	}
	objs, err := h.searchRepo(r.Context(), rp, q.Get("text"), from+size)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	total := len(objs)
	if from < len(objs) {
		objs = objs[from:]
	} else {
		objs = nil
	}
	if len(objs) > size {
		objs = objs[:size]
	}
	if objs == nil {
		objs = []searchObject{}
	}
	writeJSON(w, http.StatusOK, searchResult{Objects: objs, Total: total, Time: time.Now().UTC().Format(time.RFC1123)})
}

// searchRepo returns up to limit results for text.
func (h *Handler) searchRepo(ctx context.Context, rp *repo.Repository, text string, limit int) ([]searchObject, error) {
	switch rp.Kind {
	case repo.KindProxy:
		return h.searchUpstream(ctx, rp, text, limit)
	case repo.KindGroup:
		var out []searchObject
		seen := map[string]bool{}
		for _, m := range h.env.Members(ctx, rp) {
			objs, err := h.searchRepo(ctx, m, text, limit)
			if err != nil {
				h.env.Logger.Warn("group member search failed", "group", rp.Name, "member", m.Name, "err", err)
				continue
			}
			for _, o := range objs {
				n, _ := o.Package["name"].(string)
				if !seen[n] {
					seen[n] = true
					out = append(out, o)
				}
			}
		}
		return out, nil
	default:
		return h.searchHosted(ctx, rp, text, limit)
	}
}

func (h *Handler) searchHosted(ctx context.Context, rp *repo.Repository, text string, limit int) ([]searchObject, error) {
	terms := strings.Fields(text)
	nameQuery := ""
	if len(terms) > 0 {
		nameQuery = terms[0]
	}
	cs, err := h.env.Repos.Store.SearchComponents(ctx, store.ComponentQuery{
		RepositoryIDs: []string{rp.ID}, Name: nameQuery, Limit: 500,
	})
	if err != nil {
		return nil, err
	}
	// Results are ordered by name, newest first: keep the highest version.
	best := map[string]*store.Component{}
	var order []string
	for _, c := range cs {
		if cur, ok := best[c.Name]; !ok {
			best[c.Name] = c
			order = append(order, c.Name)
		} else if compareSemver(c.Version, cur.Version) > 0 {
			best[c.Name] = c
		}
	}
	var out []searchObject
	for _, n := range order {
		c := best[n]
		var attrs map[string]json.RawMessage
		_ = json.Unmarshal(c.Attrs, &attrs)
		pkg := map[string]any{"name": c.Name, "version": c.Version, "date": c.UpdatedAt.UTC().Format(time.RFC3339),
			"maintainers": []any{}, "links": map[string]string{}}
		if strings.HasPrefix(c.Name, "@") {
			pkg["scope"] = strings.TrimPrefix(strings.SplitN(c.Name, "/", 2)[0], "@")
		} else {
			pkg["scope"] = "unscoped"
		}
		for _, k := range []string{"description", "keywords", "author"} {
			if v, ok := attrs[k]; ok {
				pkg[k] = v
			}
		}
		if !matchesAll(c.Name, attrs, terms[min(1, len(terms)):]) {
			continue
		}
		out = append(out, searchObject{
			Package:     pkg,
			Score:       map[string]any{"final": 1, "detail": map[string]float64{"quality": 1, "popularity": 1, "maintenance": 1}},
			SearchScore: 1,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// matchesAll checks additional search terms against name, description and
// keywords.
func matchesAll(name string, attrs map[string]json.RawMessage, terms []string) bool {
	hay := strings.ToLower(name + " " + string(attrs["description"]) + " " + string(attrs["keywords"]))
	for _, t := range terms {
		if !strings.Contains(hay, strings.ToLower(t)) {
			return false
		}
	}
	return true
}

func (h *Handler) searchUpstream(ctx context.Context, rp *repo.Repository, text string, limit int) ([]searchObject, error) {
	u := proxy.JoinURL(rp.Cfg.Proxy.RemoteURL, "-/v1/search") + "?text=" + url.QueryEscape(text) + "&size=" + strconv.Itoa(min(limit, 250))
	req, err := h.env.Proxy.Request(ctx, rp, http.MethodGet, u)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.env.Proxy.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &proxy.UpstreamError{Status: resp.StatusCode, URL: u}
	}
	var res searchResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&res); err != nil {
		return nil, err
	}
	return res.Objects, nil
}

// audit forwards npm audit requests to the first proxy upstream (directly
// or through a group); hosted repositories report no advisories.
func (h *Handler) audit(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	target := h.auditUpstream(r.Context(), rp)
	if target == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	u := proxy.JoinURL(target.Cfg.Proxy.RemoteURL, "-/"+p)
	req, err := h.env.Proxy.Request(r.Context(), target, http.MethodPost, u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	req.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	for _, k := range []string{"Content-Type", "Content-Encoding", "Accept"} {
		if v := r.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := h.env.Proxy.Client.Do(req)
	if err != nil {
		h.env.Logger.Warn("npm audit upstream failed", "err", err)
		jsonError(w, http.StatusBadGateway, "audit upstream unavailable")
		return
	}
	defer resp.Body.Close()
	for _, k := range []string{"Content-Type", "Content-Encoding"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *Handler) auditUpstream(ctx context.Context, rp *repo.Repository) *repo.Repository {
	switch rp.Kind {
	case repo.KindProxy:
		return rp
	case repo.KindGroup:
		for _, m := range h.env.Members(ctx, rp) {
			if t := h.auditUpstream(ctx, m); t != nil {
				return t
			}
		}
	}
	return nil
}
