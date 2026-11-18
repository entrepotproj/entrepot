package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// errUpstreamCorrupt marks upstream content that failed digest verification.
var errUpstreamCorrupt = errors.New("upstream content failed digest verification")

// errUpstreamUnavailable marks network failures talking to the upstream.
var errUpstreamUnavailable = errors.New("upstream registry unavailable")

// upstreamBase returns the registry root URL of a proxy repository.
func upstreamBase(rp *repo.Repository) string {
	base := strings.TrimRight(rp.Cfg.Proxy.RemoteURL, "/")
	base = strings.TrimSuffix(base, "/v2")
	if u, err := url.Parse(base); err == nil {
		switch strings.ToLower(u.Host) {
		case "docker.io", "index.docker.io", "registry.hub.docker.com", "hub.docker.com":
			return "https://registry-1.docker.io"
		}
	}
	return base
}

func isDockerHub(rp *repo.Repository) bool {
	u, err := url.Parse(upstreamBase(rp))
	return err == nil && strings.EqualFold(u.Host, "registry-1.docker.io")
}

// upstreamImage maps a client image name to the upstream name: Docker Hub
// official images live under library/.
func upstreamImage(rp *repo.Repository, image string) string {
	if rp.Cfg.Proxy != nil && isDockerHub(rp) && !strings.Contains(image, "/") {
		return "library/" + image
	}
	return image
}

// ---- upstream token dance --------------------------------------------------

type cachedToken struct {
	token string
	exp   time.Time
}

type tokenCache struct {
	mu sync.Mutex
	m  map[string]cachedToken
}

func newTokenCache() *tokenCache { return &tokenCache{m: map[string]cachedToken{}} }

func (c *tokenCache) get(k string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[k]
	if !ok || time.Now().After(t.exp) {
		delete(c.m, k)
		return ""
	}
	return t.token
}

func (c *tokenCache) put(k, tok string, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 10000 {
		now := time.Now()
		for k, t := range c.m {
			if now.After(t.exp) {
				delete(c.m, k)
			}
		}
	}
	c.m[k] = cachedToken{token: tok, exp: exp}
}

// parseChallenge parses `Bearer realm="...",service="...",scope="..."`.
func parseChallenge(h string) (scheme string, params map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params = map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		var val string
		if strings.HasPrefix(v, `"`) {
			end := 1
			for end < len(v) && v[end] != '"' {
				if v[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(v) {
				val, rest = strings.ReplaceAll(v[1:], `\"`, `"`), ""
			} else {
				val, rest = strings.ReplaceAll(v[1:end], `\"`, `"`), v[end+1:]
			}
		} else {
			val, rest, _ = strings.Cut(v, ",")
		}
		params[k] = val
		rest = strings.TrimLeft(strings.TrimSpace(rest), ",")
		rest = strings.TrimSpace(rest)
	}
	return strings.ToLower(scheme), params
}

// upstreamDo performs a request against the upstream registry, handling the
// Bearer token dance (and caching tokens until they expire).
func (h *Handler) upstreamDo(ctx context.Context, rp *repo.Repository, method, rawURL, accept, scope string) (*http.Response, error) {
	key := rp.ID + "|" + scope
	send := func(tok string) (*http.Response, error) {
		req, err := h.env.Proxy.Request(ctx, rp, method, rawURL)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := h.env.Proxy.Client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w: %s %s: %v", errUpstreamUnavailable, method, redactURL(rawURL), redactErr(err))
		}
		return resp, nil
	}
	tok := h.tokens.get(key)
	resp, err := send(tok)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	scheme, params := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	if scheme != "bearer" || params["realm"] == "" {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	sc := scope
	if s := params["scope"]; s != "" {
		sc = s
	}
	tok, exp, err := h.fetchUpstreamToken(ctx, rp, params["realm"], params["service"], sc)
	if err != nil {
		return nil, err
	}
	h.tokens.put(key, tok, exp)
	return send(tok)
}

func (h *Handler) fetchUpstreamToken(ctx context.Context, rp *repo.Repository, realm, service, scope string) (string, time.Time, error) {
	ru, err := url.Parse(realm)
	if err != nil || (ru.Scheme != "https" && ru.Scheme != "http") || ru.Host == "" {
		return "", time.Time{}, fmt.Errorf("upstream advertised an invalid token realm %q", realm)
	}
	// Never send credentials over plain HTTP to a host other than the remote.
	remote, _ := url.Parse(upstreamBase(rp))
	if ru.Scheme == "http" && (remote == nil || !strings.EqualFold(remote.Host, ru.Host)) {
		return "", time.Time{}, fmt.Errorf("refusing insecure token realm %q", realm)
	}
	qv := ru.Query()
	if service != "" {
		qv.Set("service", service)
	}
	if scope != "" {
		qv.Set("scope", scope)
	}
	ru.RawQuery = qv.Encode()
	req, err := h.env.Proxy.Request(ctx, rp, http.MethodGet, ru.String())
	if err != nil {
		return "", time.Time{}, err
	}
	if pc := rp.Cfg.Proxy; pc.Username != "" {
		req.SetBasicAuth(pc.Username, pc.Password)
	}
	resp, err := h.env.Proxy.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", time.Time{}, ctx.Err()
		}
		return "", time.Time{}, fmt.Errorf("%w: token %s: %v", errUpstreamUnavailable, redactURL(ru.String()), redactErr(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusForbidden && scope != "":
		// GHCR and others deny tokens for images that do not exist (or are
		// not visible with the configured credentials).
		h.env.Logger.Info("upstream token denied; treating as not found", "repository", rp.Name, "scope", scope)
		return "", time.Time{}, proxy.ErrUpstreamNotFound
	case resp.StatusCode != http.StatusOK:
		return "", time.Time{}, &proxy.UpstreamError{Status: resp.StatusCode, URL: ru.String()}
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", time.Time{}, fmt.Errorf("upstream token response: %w", err)
	}
	tok := tr.Token
	if tok == "" {
		tok = tr.AccessToken
	}
	if tok == "" {
		return "", time.Time{}, errors.New("upstream token response has no token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if ttl > 20*time.Second {
		ttl -= 10 * time.Second
	}
	return tok, time.Now().Add(ttl), nil
}

func redactURL(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return "<invalid url>"
	}
	pu.User = nil
	pu.RawQuery = ""
	return pu.String()
}

// redactErr strips query strings (presigned CDN signatures) from URL errors.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, redactURL(ue.URL), ue.Err)
	}
	return err
}

func pullScope(up string) string { return "repository:" + up + ":pull" }

// checkStatus maps an upstream response status to an error (closing the body).
func (h *Handler) checkStatus(rp *repo.Repository, resp *http.Response, rawURL string) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		return proxy.ErrUpstreamNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		// Registries (Docker Hub included) answer 401 for images that do not
		// exist; with valid credentials the image is unknown or private.
		h.env.Logger.Info("upstream denied access; treating as not found",
			"repository", rp.Name, "url", redactURL(rawURL), "status", resp.StatusCode)
		return proxy.ErrUpstreamNotFound
	}
	return &proxy.UpstreamError{Status: resp.StatusCode, URL: rawURL}
}

// ---- proxied manifests and blobs ------------------------------------------

func (h *Handler) proxyManifest(ctx context.Context, rp *repo.Repository, image string, d storage.Digest, tag string) (*store.Asset, error) {
	up := upstreamImage(rp, image)
	if d != "" {
		return h.env.Proxy.Get(ctx, rp, manifestPath(up, d), -1, func(ctx context.Context, _ *store.Asset) (*proxy.FetchResult, error) {
			res, _, _, err := h.fetchManifest(ctx, rp, up, d.String(), d)
			return res, err
		})
	}
	return h.env.Proxy.Get(ctx, rp, tagPath(up, tag), rp.Cfg.Proxy.MetadataTTL(), func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		if existing != nil {
			// Revalidate cheaply: HEAD requests do not count towards Docker
			// Hub pull rate limits.
			cur, err := h.headManifest(ctx, rp, up, tag)
			if err == nil && cur == existing.Digest {
				return &proxy.FetchResult{NotModified: true}, nil
			}
			if errors.Is(err, proxy.ErrUpstreamNotFound) {
				return nil, err
			}
		}
		res, body, md, err := h.fetchManifest(ctx, rp, up, tag, "")
		if err != nil {
			return nil, err
		}
		// Keep the manifest addressable by digest too.
		if _, err := h.env.Repos.Put(ctx, rp, repo.PutOptions{
			Path:           manifestPath(up, md),
			Body:           bytes.NewReader(body),
			ContentType:    res.ContentType,
			ExpectedDigest: md,
			Attrs:          mustJSON(map[string]any{"mediaType": res.ContentType}),
			CreatedBy:      "proxy:" + rp.Name,
			Cached:         true,
		}); err != nil {
			return nil, err
		}
		res.Attrs["digest"] = md.String()
		res.Component = &repo.ComponentRef{Name: up, Version: tag,
			Attrs: mustJSON(map[string]any{"digest": md.String(), "mediaType": res.ContentType})}
		return res, nil
	})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (h *Handler) manifestURL(rp *repo.Repository, up, ref string) string {
	return upstreamBase(rp) + "/v2/" + up + "/manifests/" + ref
}

func (h *Handler) headManifest(ctx context.Context, rp *repo.Repository, up, ref string) (string, error) {
	u := h.manifestURL(rp, up, ref)
	resp, err := h.upstreamDo(ctx, rp, http.MethodHead, u, manifestAccept, pullScope(up))
	if err != nil {
		return "", err
	}
	if err := h.checkStatus(rp, resp, u); err != nil {
		return "", err
	}
	resp.Body.Close()
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", errors.New("upstream HEAD returned no Docker-Content-Digest")
	}
	return d, nil
}

// fetchManifest GETs a manifest and verifies its digest (against want, and
// against the upstream's Docker-Content-Digest).
func (h *Handler) fetchManifest(ctx context.Context, rp *repo.Repository, up, ref string, want storage.Digest) (*proxy.FetchResult, []byte, storage.Digest, error) {
	u := h.manifestURL(rp, up, ref)
	resp, err := h.upstreamDo(ctx, rp, http.MethodGet, u, manifestAccept, pullScope(up))
	if err != nil {
		return nil, nil, "", err
	}
	if err := h.checkStatus(rp, resp, u); err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifest+1))
	if err != nil {
		return nil, nil, "", fmt.Errorf("read upstream manifest: %w", err)
	}
	if len(body) > MaxManifest {
		return nil, nil, "", fmt.Errorf("upstream manifest %s exceeds %d bytes", up+":"+ref, MaxManifest)
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, "", fmt.Errorf("upstream returned an invalid manifest for %s: %w", up+":"+ref, err)
	}
	mt, err := mediaTypeOf(resp.Header.Get("Content-Type"), &doc)
	if err != nil {
		// Be lenient with upstream Content-Type quirks; trust the document.
		mt = doc.MediaType
	}
	if mt == MediaDockerSchema1 || mt == MediaDockerSchema1JWS {
		return nil, nil, "", format.BadRequest("upstream only offers a Docker schema1 manifest for %s, which is not supported", up+":"+ref)
	}
	if mt == "" {
		mt = MediaOCIManifest
	}
	d := storage.DigestBytes(body)
	if want != "" && d != want {
		return nil, nil, "", fmt.Errorf("%w: upstream manifest %s has digest %s", errUpstreamCorrupt, want, d)
	}
	if hd := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(hd, "sha256:") && hd != d.String() {
		return nil, nil, "", fmt.Errorf("%w: upstream advertised %s for %s but the content hashes to %s",
			errUpstreamCorrupt, hd, up+":"+ref, d)
	}
	return &proxy.FetchResult{
		Body:        io.NopCloser(bytes.NewReader(body)),
		ContentType: mt,
		Attrs:       map[string]any{"mediaType": mt},
	}, body, d, nil
}

func (h *Handler) proxyBlob(ctx context.Context, rp *repo.Repository, image string, d storage.Digest) (*store.Asset, error) {
	up := upstreamImage(rp, image)
	return h.env.Proxy.Get(ctx, rp, blobPath(up, d), -1, func(ctx context.Context, _ *store.Asset) (*proxy.FetchResult, error) {
		u := upstreamBase(rp) + "/v2/" + up + "/blobs/" + d.String()
		// The HTTP client follows redirects (e.g. Docker Hub -> CDN); Go drops
		// the Authorization header when redirected to another host.
		resp, err := h.upstreamDo(ctx, rp, http.MethodGet, u, "", pullScope(up))
		if err != nil {
			return nil, err
		}
		if err := h.checkStatus(rp, resp, u); err != nil {
			return nil, err
		}
		return &proxy.FetchResult{
			Body:        &verifyingReader{rc: resp.Body, want: d, h: sha256.New()},
			ContentType: "application/octet-stream",
		}, nil
	})
}

// verifyingReader fails at EOF if the content does not hash to want, so a
// corrupted upstream download is never stored.
type verifyingReader struct {
	rc   io.ReadCloser
	want storage.Digest
	h    hash.Hash
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	v.h.Write(p[:n]) //nolint:errcheck // hash writes never fail
	if err == io.EOF {
		if got := "sha256:" + hex.EncodeToString(v.h.Sum(nil)); got != v.want.String() {
			return n, fmt.Errorf("%w: upstream blob %s hashes to %s", errUpstreamCorrupt, v.want, got)
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.rc.Close() }

// upstreamTags fetches the full tag list from the upstream, following
// pagination links.
func (h *Handler) upstreamTags(ctx context.Context, rp *repo.Repository, up string) ([]string, error) {
	if !rp.Online {
		return nil, errors.New("repository is offline")
	}
	next := upstreamBase(rp) + "/v2/" + up + "/tags/list?n=1000"
	var tags []string
	for page := 0; next != "" && page < 50; page++ {
		resp, err := h.upstreamDo(ctx, rp, http.MethodGet, next, "application/json", pullScope(up))
		if errors.Is(err, proxy.ErrUpstreamNotFound) {
			return nil, repo.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if err := h.checkStatus(rp, resp, next); err != nil {
			if errors.Is(err, proxy.ErrUpstreamNotFound) {
				return nil, repo.ErrNotFound
			}
			return nil, err
		}
		var tl struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&tl)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("upstream tags list: %w", err)
		}
		tags = append(tags, tl.Tags...)
		next = nextLink(next, link)
	}
	return tags, nil
}

// nextLink resolves a `<url>; rel="next"` Link header against cur.
func nextLink(cur, link string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		target, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.Contains(params, `rel="next"`) && !strings.Contains(params, "rel=next") {
			continue
		}
		target = strings.Trim(strings.TrimSpace(target), "<>")
		base, err := url.Parse(cur)
		if err != nil {
			return ""
		}
		ref, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return base.ResolveReference(ref).String()
	}
	return ""
}
