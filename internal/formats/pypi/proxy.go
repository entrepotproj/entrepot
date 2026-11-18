package pypi

import (
	"context"
	"crypto/md5" //nolint:gosec // legacy PyPI digests
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

const (
	maxIndexSize   = 128 << 20
	upstreamAccept = jsonType + ", " + htmlType + ";q=0.2, text/html;q=0.1"
)

// upstreamIndexURL is the upstream project page URL. The remote may be the
// server root (https://pypi.org) or the simple index itself
// (https://example.com/repository/pypi/simple).
func upstreamIndexURL(remote, project string) string {
	base := strings.TrimRight(remote, "/")
	if !strings.HasSuffix(base, "/simple") {
		base += "/simple"
	}
	return base + "/" + url.PathEscape(project) + "/"
}

type indexAttrs struct {
	UpstreamURL string `json:"upstreamUrl"`
}

// proxyIndex returns the cached upstream project page asset.
func (h *Handler) proxyIndex(ctx context.Context, rp *repo.Repository, project string, ttl time.Duration) (*store.Asset, error) {
	return h.env.Proxy.Get(ctx, rp, "simple/"+project, ttl, func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		u := upstreamIndexURL(rp.Cfg.Proxy.RemoteURL, project)
		res, err := h.env.Proxy.FetchURL(ctx, rp, u, existing, http.Header{"Accept": {upstreamAccept}})
		if err != nil || res.NotModified {
			return res, err
		}
		if res.ContentType == "" {
			res.ContentType = "text/html"
		}
		res.Attrs = map[string]any{"upstreamUrl": u, "project": project}
		return res, nil
	})
}

func (h *Handler) proxyPage(ctx context.Context, rp *repo.Repository, project string, ttl time.Duration) (*projectPage, error) {
	a, err := h.proxyIndex(ctx, rp, project, ttl)
	if err != nil {
		return nil, err
	}
	body, err := h.env.Repos.ReadAll(ctx, rp, a, maxIndexSize)
	if err != nil {
		return nil, err
	}
	var attrs indexAttrs
	_ = json.Unmarshal(a.Attrs, &attrs)
	if attrs.UpstreamURL == "" {
		attrs.UpstreamURL = upstreamIndexURL(rp.Cfg.Proxy.RemoteURL, project)
	}
	return parseIndex(body, a.ContentType, attrs.UpstreamURL, project)
}

// find locates a file, consulting upstreams (proxy) or members (group).
func (h *Handler) find(ctx context.Context, rp *repo.Repository, p string) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		a, err := h.proxyFile(ctx, rp, p)
		return rp, a, err
	case repo.KindGroup:
		for _, m := range h.env.Members(ctx, rp) {
			owner, a, err := h.find(ctx, m, p)
			if err == nil {
				return owner, a, nil
			}
			if !isNotFound(err) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "path", p, "err", err)
			}
		}
		return nil, nil, repo.ErrNotFound
	default:
		a, err := h.env.Repos.GetAsset(ctx, rp, p)
		return rp, a, err
	}
}

// lookupUpstreamFile finds a file on the cached upstream project page,
// revalidating the page once when the file is not listed (new release).
func (h *Handler) lookupUpstreamFile(ctx context.Context, rp *repo.Repository, fp filePath) (*distFile, error) {
	for _, ttl := range []time.Duration{rp.Cfg.Proxy.MetadataTTL(), 0} {
		pg, err := h.proxyPage(ctx, rp, fp.Project, ttl)
		if err != nil {
			if isNotFound(err) {
				return nil, proxy.ErrUpstreamNotFound
			}
			return nil, err
		}
		for i := range pg.Files {
			f := &pg.Files[i]
			if f.Filename == fp.Dist {
				if f.Path != filePathFor(fp.Project, fp.Version, fp.Dist) {
					return nil, proxy.ErrUpstreamNotFound
				}
				return f, nil
			}
		}
	}
	return nil, proxy.ErrUpstreamNotFound
}

func (h *Handler) proxyFile(ctx context.Context, rp *repo.Repository, p string) (*store.Asset, error) {
	fp, ok := parseFilePath(p)
	if !ok {
		return nil, repo.ErrNotFound
	}
	return h.env.Proxy.Get(ctx, rp, p, rp.Cfg.Proxy.ContentTTL(), func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		f, err := h.lookupUpstreamFile(ctx, rp, fp)
		if err != nil {
			return nil, err
		}
		target, hashes := f.URL, f.Hashes
		if fp.Metadata {
			if !f.HasMetadata {
				return nil, proxy.ErrUpstreamNotFound
			}
			target, hashes = f.URL+metadataSuffix, f.MetadataHashes
		}
		res, err := h.env.Proxy.FetchURL(ctx, rp, target, existing, nil)
		if err != nil || res.NotModified {
			return res, err
		}
		res.ContentType = contentType(fp.Filename)
		res.Body = verifying(res.Body, hashes)
		attrs := map[string]any{"filename": fp.Filename, "upstreamUrl": target}
		if f.RequiresPython != "" && !fp.Metadata {
			attrs["requires_python"] = f.RequiresPython
		}
		res.Attrs = attrs
		if f.Version != "" {
			res.Component = &repo.ComponentRef{Name: fp.Project, Version: f.Version}
		}
		return res, nil
	})
}

// verifying wraps body so that reading it to EOF fails when its digest does
// not match the strongest known hash, keeping corrupt content out of the
// cache.
func verifying(body io.ReadCloser, hashes map[string]string) io.ReadCloser {
	for _, alg := range []string{"sha256", "sha512", "md5"} {
		want := strings.ToLower(hashes[alg])
		if want == "" {
			continue
		}
		var hh hash.Hash
		switch alg {
		case "sha256":
			hh = sha256.New()
		case "sha512":
			hh = sha512.New()
		case "md5":
			hh = md5.New() //nolint:gosec
		}
		return &verifyReader{ReadCloser: body, h: hh, alg: alg, want: want}
	}
	return body
}

var errDigestMismatch = errors.New("upstream content does not match its published digest")

type verifyReader struct {
	io.ReadCloser
	h    hash.Hash
	alg  string
	want string
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.ReadCloser.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.want {
			return n, fmt.Errorf("%w (%s %s, expected %s)", errDigestMismatch, v.alg, got, v.want)
		}
	}
	return n, err
}
