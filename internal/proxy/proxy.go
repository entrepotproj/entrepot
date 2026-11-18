// Package proxy implements the pull-through cache shared by all formats.
//
// Formats describe *what* to fetch (a FetchFunc); the Cache decides *when*:
// it serves fresh cached assets, revalidates stale ones (conditional GETs),
// collapses concurrent misses with singleflight, remembers upstream 404s and
// falls back to stale content when the upstream is unavailable.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

var (
	// ErrUpstreamNotFound means the upstream answered 404/410.
	ErrUpstreamNotFound = errors.New("not found upstream")
)

// UpstreamError carries a non-success upstream status.
type UpstreamError struct {
	Status int
	URL    string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream %s returned %d", redact(e.URL), e.Status)
}

// FetchResult is returned by a FetchFunc.
type FetchResult struct {
	// NotModified: the cached asset is still valid (revalidation succeeded).
	NotModified bool
	Body        io.ReadCloser
	ContentType string
	// Attrs to store on the asset (merged with upstream validators).
	Attrs     map[string]any
	Component *repo.ComponentRef
	// Validators from the upstream response.
	ETag         string
	LastModified string
}

// FetchFunc fetches path from the upstream. existing is the currently cached
// asset (nil on a miss), useful for conditional requests.
type FetchFunc func(ctx context.Context, existing *store.Asset) (*FetchResult, error)

type Cache struct {
	// Allow, when set, is consulted before any upstream fetch (routing
	// rules). Disallowed paths are reported as not found.
	Allow func(ctx context.Context, rp *repo.Repository, path string) bool

	repos  *repo.Service
	Client *http.Client
	ua     string
	logger *slog.Logger

	sf  singleflight.Group
	neg sync.Map // key -> time.Time expiry
}

func NewCache(repos *repo.Service, timeout time.Duration, userAgent string, logger *slog.Logger) *Cache {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 32
	transport.ResponseHeaderTimeout = timeout
	return &Cache{
		repos:  repos,
		Client: &http.Client{Transport: transport},
		ua:     userAgent,
		logger: logger,
	}
}

// Get returns the cached asset for path, fetching or revalidating it as
// needed. ttl < 0 means cached content never expires.
func (c *Cache) Get(ctx context.Context, rp *repo.Repository, path string, ttl time.Duration, fetch FetchFunc) (*store.Asset, error) {
	existing, err := c.repos.GetAsset(ctx, rp, path)
	if err != nil && !errors.Is(err, repo.ErrNotFound) {
		return nil, err
	}
	if existing != nil && fresh(existing, ttl) {
		return existing, nil
	}
	if !rp.Online {
		if existing != nil {
			return existing, nil
		}
		return nil, repo.ErrNotFound
	}
	if c.Allow != nil && !c.Allow(ctx, rp, path) {
		return nil, repo.ErrNotFound
	}
	key := rp.ID + "\x00" + path
	if exp, ok := c.neg.Load(key); ok && existing == nil {
		if time.Now().Before(exp.(time.Time)) {
			return nil, repo.ErrNotFound
		}
		c.neg.Delete(key)
	}

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Shared fetch: detach from a single client's cancellation.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
		defer cancel()
		return c.fetchAndStore(fctx, rp, path, existing, fetch)
	})
	if err != nil {
		if errors.Is(err, ErrUpstreamNotFound) {
			if neg := rp.Cfg.Proxy.NegativeTTL(); neg > 0 {
				c.neg.Store(key, time.Now().Add(neg))
			}
			if existing != nil {
				// Upstream removed it; keep serving what we have.
				return existing, nil
			}
			return nil, repo.ErrNotFound
		}
		if existing != nil {
			c.logger.Warn("upstream failed, serving stale content", "repository", rp.Name, "path", path, "err", err)
			return existing, nil
		}
		return nil, err
	}
	return v.(*store.Asset), nil
}

func fresh(a *store.Asset, ttl time.Duration) bool {
	if ttl < 0 {
		return true
	}
	if a.CachedAt == nil {
		// Hosted content placed into a proxy repo (e.g. via API) never expires.
		return true
	}
	return time.Since(*a.CachedAt) < ttl
}

func (c *Cache) fetchAndStore(ctx context.Context, rp *repo.Repository, path string, existing *store.Asset, fetch FetchFunc) (*store.Asset, error) {
	res, err := fetch(ctx, existing)
	if err != nil {
		return nil, err
	}
	if res.NotModified {
		if existing == nil {
			return nil, errors.New("upstream returned 304 without a cached asset")
		}
		if err := c.repos.Store.TouchCached(ctx, existing.ID); err != nil {
			return nil, err
		}
		return existing, nil
	}
	defer res.Body.Close()
	attrs := map[string]any{}
	for k, v := range res.Attrs {
		attrs[k] = v
	}
	if res.ETag != "" || res.LastModified != "" {
		attrs["upstream"] = map[string]string{"etag": res.ETag, "lastModified": res.LastModified}
	}
	rawAttrs, _ := json.Marshal(attrs)
	ct := res.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	return c.repos.Put(ctx, rp, repo.PutOptions{
		Path:        path,
		Body:        res.Body,
		ContentType: ct,
		Attrs:       rawAttrs,
		CreatedBy:   "proxy:" + rp.Name,
		Component:   res.Component,
		Cached:      true,
	})
}

// Request builds an upstream request with the repository's credentials. The
// credentials are only attached when the target host matches the configured
// remote URL host, so redirects to CDNs never receive them.
func (c *Cache) Request(ctx context.Context, rp *repo.Repository, method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	if pc := rp.Cfg.Proxy; pc != nil && pc.Username != "" {
		if remote, err := url.Parse(pc.RemoteURL); err == nil && strings.EqualFold(remote.Host, req.URL.Host) {
			req.SetBasicAuth(pc.Username, pc.Password)
		}
	}
	return req, nil
}

// Validators returns stored upstream ETag/Last-Modified of an asset.
func Validators(a *store.Asset) (etag, lastModified string) {
	if a == nil {
		return "", ""
	}
	var attrs struct {
		Upstream struct {
			ETag         string `json:"etag"`
			LastModified string `json:"lastModified"`
		} `json:"upstream"`
	}
	_ = json.Unmarshal(a.Attrs, &attrs)
	return attrs.Upstream.ETag, attrs.Upstream.LastModified
}

// FetchURL performs a (conditional) GET of rawURL. It maps 404/410 to
// ErrUpstreamNotFound and 304 to NotModified. Extra headers may be supplied.
func (c *Cache) FetchURL(ctx context.Context, rp *repo.Repository, rawURL string, existing *store.Asset, headers http.Header) (*FetchResult, error) {
	req, err := c.Request(ctx, rp, http.MethodGet, rawURL)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if etag, lm := Validators(existing); etag != "" || lm != "" {
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if lm != "" {
			req.Header.Set("If-Modified-Since", lm)
		}
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", redact(rawURL), err)
	}
	switch {
	case resp.StatusCode == http.StatusNotModified:
		resp.Body.Close()
		return &FetchResult{NotModified: true}, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		resp.Body.Close()
		return nil, ErrUpstreamNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		resp.Body.Close()
		return nil, &UpstreamError{Status: resp.StatusCode, URL: rawURL}
	}
	return &FetchResult{
		Body:         resp.Body,
		ContentType:  resp.Header.Get("Content-Type"),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// JoinURL joins the repository's remote URL with a path.
func JoinURL(base, p string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(p, "/")
}

func redact(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return "<invalid url>"
	}
	pu.User = nil
	pu.RawQuery = ""
	return pu.String()
}
