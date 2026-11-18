package apt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// maxRelease bounds the size of a cached (In)Release file that is parsed.
const maxRelease = 64 << 20

func (h *Handler) proxyGet(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	if p == "" || strings.HasSuffix(p, "/") {
		http.Error(w, "directory listings are not available for apt proxy repositories", http.StatusNotFound)
		return
	}
	a, err := h.proxyAsset(r.Context(), rp, p)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, rp, a, repo.ServeOptions{ContentType: contentType(p), NoRedirect: strings.HasPrefix(p, "dists/")})
}

// upstreamURL escapes each path segment for the remote.
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
	base := p[strings.LastIndex(p, "/")+1:]
	switch {
	case strings.Contains(p, "/by-hash/"):
		ttl = pc.ContentTTL()
	case strings.HasPrefix(p, "dists/"):
		switch base {
		case "InRelease", "Release":
		case "Release.gpg":
			ttl = h.signatureTTL(ctx, rp, p, ttl)
		default:
			ttl = h.indexTTL(ctx, rp, p, ttl)
		}
	case strings.HasPrefix(p, "pool/"):
		ttl = pc.ContentTTL()
		if pkg, ver, arch, ok := parseDebFilename(base); ok {
			attrs, _ := json.Marshal(map[string]string{"architecture": arch})
			comp = &repo.ComponentRef{Name: pkg, Version: ver, Attrs: attrs}
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

// signatureTTL makes Release.gpg follow its Release file: when Release was
// cached after the signature, the signature is revalidated.
func (h *Handler) signatureTTL(ctx context.Context, rp *repo.Repository, p string, ttl time.Duration) time.Duration {
	sig, err := h.env.Repos.GetAsset(ctx, rp, p)
	if err != nil {
		return ttl
	}
	rel, err := h.env.Repos.GetAsset(ctx, rp, strings.TrimSuffix(p, ".gpg"))
	if err != nil || rel.CachedAt == nil || sig.CachedAt == nil {
		return ttl
	}
	if sig.CachedAt.Before(*rel.CachedAt) {
		return 0
	}
	return ttl
}

// indexTTL decides whether a cached index file (Packages.xz, ...) is still
// the one the cached (In)Release describes: matching files never expire,
// mismatching ones are refetched immediately.
func (h *Handler) indexTTL(ctx context.Context, rp *repo.Repository, p string, ttl time.Duration) time.Duration {
	cur, err := h.env.Repos.GetAsset(ctx, rp, p)
	if err != nil {
		return ttl // not cached yet: fetched anyway
	}
	segs := strings.Split(p, "/")
	// Walk up to the nearest directory holding a cached release file.
	for i := len(segs) - 1; i >= 2; i-- {
		dir := strings.Join(segs[:i], "/")
		rel := h.newestRelease(ctx, rp, dir)
		if rel == nil {
			continue
		}
		sums := h.hashes.get(ctx, h, rp, rel)
		if len(sums) == 0 {
			continue // e.g. a component-level Release without checksums
		}
		want, ok := sums[strings.Join(segs[i:], "/")]
		if !ok {
			return ttl
		}
		if cur.Digest == "sha256:"+want {
			return -1
		}
		return 0
	}
	return ttl
}

func (h *Handler) newestRelease(ctx context.Context, rp *repo.Repository, dir string) *store.Asset {
	var best *store.Asset
	for _, name := range []string{"InRelease", "Release"} {
		a, err := h.env.Repos.GetAsset(ctx, rp, dir+"/"+name)
		if err != nil {
			continue
		}
		if best == nil || a.UpdatedAt.After(best.UpdatedAt) {
			best = a
		}
	}
	return best
}

// releaseCache memoises the SHA256 sections of cached release files by
// content digest.
type releaseCache struct {
	mu sync.Mutex
	m  map[string]map[string]string
}

func (c *releaseCache) get(ctx context.Context, h *Handler, rp *repo.Repository, a *store.Asset) map[string]string {
	c.mu.Lock()
	sums, ok := c.m[a.Digest]
	c.mu.Unlock()
	if ok {
		return sums
	}
	body, err := h.env.Repos.ReadAll(ctx, rp, a, maxRelease)
	if err != nil {
		h.env.Logger.Warn("apt: read cached release", "repository", rp.Name, "path", a.Path, "err", err)
		return nil
	}
	sums = parseReleaseSHA256(body)
	c.mu.Lock()
	if c.m == nil || len(c.m) > 256 {
		c.m = map[string]map[string]string{}
	}
	c.m[a.Digest] = sums
	c.mu.Unlock()
	return sums
}

// parseReleaseSHA256 returns path -> sha256 from a Release or InRelease file.
func parseReleaseSHA256(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	in := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if in {
				break
			}
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			in = strings.TrimSpace(line) == "SHA256:"
			if strings.HasPrefix(line, "-----BEGIN PGP SIGNATURE") {
				break
			}
			continue
		}
		if !in {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 3 {
			out[f[2]] = strings.ToLower(f[0])
		}
	}
	return out
}
