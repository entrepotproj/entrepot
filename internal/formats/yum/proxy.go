package yum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

// checksumNamed matches repodata files named after their checksum
// ("{hex}-primary.xml.gz"), which never change.
var checksumNamed = regexp.MustCompile(`^[0-9a-f]{32,128}-`)

func (h *Handler) proxyGet(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	if p == "entrepot.repo" || strings.HasSuffix(p, "/entrepot.repo") {
		h.serveRepoFile(w, r, rp, strings.TrimSuffix(p, "entrepot.repo"))
		return
	}
	if p == "" || strings.HasSuffix(p, "/") {
		http.Error(w, "directory listings are not available for yum proxy repositories", http.StatusNotFound)
		return
	}
	a, err := h.proxyAsset(r.Context(), rp, p)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, rp, a, repo.ServeOptions{ContentType: contentType(p), NoRedirect: strings.Contains(p, "repodata/")})
}

func upstreamURL(remote, p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return proxy.JoinURL(remote, strings.Join(segs, "/"))
}

func (h *Handler) proxyAsset(ctx context.Context, rp *repo.Repository, p string) (*store.Asset, error) {
	pc := rp.Cfg.Proxy
	ttl := pc.MetadataTTL()
	var comp *repo.ComponentRef
	dir, base := "", p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		dir, base = p[:i], p[i+1:]
	}
	inRepodata := dir == "repodata" || strings.HasSuffix(dir, "/repodata")
	switch {
	case inRepodata && base == "repomd.xml":
	case inRepodata && base == "repomd.xml.asc", inRepodata && base == "repomd.xml.key":
		ttl = h.followTTL(ctx, rp, p, dir+"/repomd.xml", ttl)
	case inRepodata && checksumNamed.MatchString(base):
		ttl = pc.ContentTTL()
	case strings.HasSuffix(base, ".rpm"):
		ttl = pc.ContentTTL()
		if name, ver, arch, ok := parseRPMFilename(base); ok {
			attrs, _ := json.Marshal(map[string]string{"arch": arch})
			comp = &repo.ComponentRef{Name: name, Version: ver, Attrs: attrs}
		}
	}
	return h.env.Proxy.Get(ctx, rp, p, ttl, func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		u := upstreamURL(pc.RemoteURL, p)
		res, err := h.env.Proxy.FetchURL(ctx, rp, u, existing, nil)
		if err != nil || res.NotModified {
			return res, err
		}
		res.ContentType = contentType(p)
		res.Attrs = map[string]any{"upstreamUrl": u}
		res.Component = comp
		return res, nil
	})
}

// followTTL revalidates a file (repomd.xml.asc) whenever the file it
// belongs to (repomd.xml) was cached more recently.
func (h *Handler) followTTL(ctx context.Context, rp *repo.Repository, p, leader string, ttl time.Duration) time.Duration {
	cur, err := h.env.Repos.GetAsset(ctx, rp, p)
	if err != nil {
		return ttl
	}
	lead, err := h.env.Repos.GetAsset(ctx, rp, leader)
	if err != nil || lead.CachedAt == nil || cur.CachedAt == nil {
		return ttl
	}
	if cur.CachedAt.Before(*lead.CachedAt) {
		return 0
	}
	return ttl
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	if rp.IsHosted() && !strings.HasSuffix(p, ".rpm") {
		http.Error(w, "only packages (*.rpm) can be deleted; repodata is regenerated automatically", http.StatusBadRequest)
		return
	}
	a, err := h.env.Repos.GetAsset(ctx, rp, p)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	if rp.IsHosted() {
		if err := h.AfterDelete(ctx, rp, []*store.Asset{a}); err != nil {
			h.env.WriteError(w, r, fmt.Errorf("regenerate repodata: %w", err))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
