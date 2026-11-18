package npm

import (
	"context"
	"crypto/sha1" //nolint:gosec // npm shasum
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
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
	abbreviatedType = "application/vnd.npm.install-v1+json"
	maxPackument    = 256 << 20
)

func packumentPath(name string) string     { return name + "/package.json" }
func tarballPath(name, file string) string { return name + "/-/" + file }

func (h *Handler) repoURL(r *http.Request, rp *repo.Repository) string {
	return h.env.URLs.BaseURL(r) + "/repository/" + url.PathEscape(rp.Name) + "/"
}

// wantsAbbreviated reports whether the client prefers the abbreviated
// ("corgi") document over full JSON.
func wantsAbbreviated(r *http.Request) bool {
	if r.URL.Query().Get("write") == "true" {
		return false
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, abbreviatedType) && !strings.HasPrefix(strings.TrimSpace(accept), "application/json")
}

func (h *Handler) getPackument(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name string) {
	pk, err := h.packument(r.Context(), rp, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pk.rewrite(h.repoURL(r, rp), name)
	ct := "application/json"
	var body []byte
	if wantsAbbreviated(r) {
		ct = abbreviatedType
		body = marshal(pk.abbreviated())
	} else {
		body = pk.bytes()
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "no-cache")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(body)
}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, spec string) {
	pk, err := h.packument(r.Context(), rp, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pk.rewrite(h.repoURL(r, rp), name)
	v := spec
	if t, ok := pk.DistTags[spec]; ok {
		v = t
	}
	man, ok := pk.Versions[v]
	if !ok {
		jsonError(w, http.StatusNotFound, "version not found: "+spec)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(marshal(man))
}

func (h *Handler) getTarball(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, file string) {
	if !validFile(file) {
		jsonError(w, http.StatusBadRequest, "invalid tarball name")
		return
	}
	owner, a, err := h.findTarball(r.Context(), rp, name, file)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{})
}

// packument returns the package document of rp (dist.tarball not yet
// rewritten).
func (h *Handler) packument(ctx context.Context, rp *repo.Repository, name string) (*packument, error) {
	switch rp.Kind {
	case repo.KindProxy:
		return h.proxyPackument(ctx, rp, name, rp.Cfg.Proxy.MetadataTTL())
	case repo.KindGroup:
		return h.groupPackument(ctx, rp, name)
	default:
		pk, _, err := h.hostedPackument(ctx, rp, name)
		if err == nil && len(pk.Versions) == 0 {
			err = repo.ErrNotFound
		}
		return pk, err
	}
}

// hostedPackument loads the stored packument, dropping versions whose
// tarball no longer exists (e.g. deleted through the management API).
func (h *Handler) hostedPackument(ctx context.Context, rp *repo.Repository, name string) (*packument, *store.Asset, error) {
	a, err := h.env.Repos.GetAsset(ctx, rp, packumentPath(name))
	if err != nil {
		return nil, nil, err
	}
	b, err := h.env.Repos.ReadAll(ctx, rp, a, maxPackument)
	if err != nil {
		return nil, nil, err
	}
	pk, err := parsePackument(b)
	if err != nil {
		return nil, nil, err
	}
	files, err := h.tarballs(ctx, rp, name)
	if err != nil {
		return nil, nil, err
	}
	for v, man := range pk.Versions {
		if !files[tarballFile(name, v, man)] {
			delete(pk.Versions, v)
		}
	}
	pk.fixTags()
	return pk, a, nil
}

// tarballs lists the tarball file names stored for a package.
func (h *Handler) tarballs(ctx context.Context, rp *repo.Repository, name string) (map[string]bool, error) {
	prefix := name + "/-/"
	out := map[string]bool{}
	after := ""
	for {
		batch, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, prefix, after, 1000)
		if err != nil {
			return nil, err
		}
		for _, a := range batch {
			out[strings.TrimPrefix(a.Path, prefix)] = true
		}
		if len(batch) < 1000 {
			return out, nil
		}
		after = batch[len(batch)-1].Path
	}
}

func (h *Handler) proxyPackumentAsset(ctx context.Context, rp *repo.Repository, name string, ttl time.Duration) (*store.Asset, error) {
	return h.env.Proxy.Get(ctx, rp, packumentPath(name), ttl, func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		res, err := h.env.Proxy.FetchURL(ctx, rp, proxy.JoinURL(rp.Cfg.Proxy.RemoteURL, escapedName(name)), existing,
			http.Header{"Accept": {"application/json"}})
		if err != nil || res.NotModified {
			return res, err
		}
		res.ContentType = "application/json"
		return res, nil
	})
}

func (h *Handler) proxyPackument(ctx context.Context, rp *repo.Repository, name string, ttl time.Duration) (*packument, error) {
	a, err := h.proxyPackumentAsset(ctx, rp, name, ttl)
	if err != nil {
		return nil, err
	}
	b, err := h.env.Repos.ReadAll(ctx, rp, a, maxPackument)
	if err != nil {
		return nil, err
	}
	pk, err := parsePackument(b)
	if err != nil {
		return nil, err
	}
	if len(pk.Versions) == 0 {
		// e.g. an unpublished package ("time": {"unpublished": ...}).
		return nil, repo.ErrNotFound
	}
	return pk, nil
}

func (h *Handler) groupPackument(ctx context.Context, rp *repo.Repository, name string) (*packument, error) {
	var merged *packument
	for _, m := range h.env.Members(ctx, rp) {
		pk, err := h.packument(ctx, m, name)
		if err != nil {
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "package", name, "err", err)
			}
			continue
		}
		if merged == nil {
			merged = pk
			continue
		}
		for v, man := range pk.Versions {
			if _, ok := merged.Versions[v]; !ok {
				merged.Versions[v] = man
			}
		}
		for t, v := range pk.DistTags {
			if _, ok := merged.DistTags[t]; !ok {
				merged.DistTags[t] = v
			}
		}
		for k, v := range pk.Time {
			cur, ok := merged.Time[k]
			if !ok || (k == "modified" && string(v) > string(cur)) {
				merged.Time[k] = v
			}
		}
	}
	if merged == nil {
		return nil, repo.ErrNotFound
	}
	// Group documents are synthesised; a revision would be meaningless.
	delete(merged.Fields, "_rev")
	return merged, nil
}

// findTarball locates a tarball, consulting upstreams or members.
func (h *Handler) findTarball(ctx context.Context, rp *repo.Repository, name, file string) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		a, err := h.proxyTarball(ctx, rp, name, file)
		return rp, a, err
	case repo.KindGroup:
		for _, m := range h.env.Members(ctx, rp) {
			owner, a, err := h.findTarball(ctx, m, name, file)
			if err == nil {
				return owner, a, nil
			}
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "file", file, "err", err)
			}
		}
		return nil, nil, repo.ErrNotFound
	default:
		a, err := h.env.Repos.GetAsset(ctx, rp, tarballPath(name, file))
		return rp, a, err
	}
}

func (h *Handler) proxyTarball(ctx context.Context, rp *repo.Repository, name, file string) (*store.Asset, error) {
	return h.env.Proxy.Get(ctx, rp, tarballPath(name, file), rp.Cfg.Proxy.ContentTTL(), func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		version, man, err := h.upstreamVersion(ctx, rp, name, file)
		if err != nil {
			return nil, err
		}
		d := dist(man)
		target := rawStr(d, "tarball")
		base, _ := url.Parse(strings.TrimRight(rp.Cfg.Proxy.RemoteURL, "/") + "/")
		if u, err := base.Parse(target); err == nil && target != "" && (u.Scheme == "http" || u.Scheme == "https") {
			target = u.String()
		} else {
			target = proxy.JoinURL(rp.Cfg.Proxy.RemoteURL, pkgURL(name)+"/-/"+url.PathEscape(file))
		}
		res, err := h.env.Proxy.FetchURL(ctx, rp, target, existing, nil)
		if err != nil || res.NotModified {
			return res, err
		}
		res.Body, err = verifying(res.Body, rawStr(d, "integrity"), rawStr(d, "shasum"))
		if err != nil {
			res.Body.Close()
			return nil, err
		}
		res.ContentType = "application/octet-stream"
		res.Attrs = map[string]any{"upstreamUrl": target, "integrity": rawStr(d, "integrity"), "shasum": rawStr(d, "shasum")}
		res.Component = &repo.ComponentRef{Name: name, Version: version, Attrs: componentAttrs(man)}
		return res, nil
	})
}

// upstreamVersion finds the version whose tarball is file, revalidating the
// cached packument once when it is not listed (a new release).
func (h *Handler) upstreamVersion(ctx context.Context, rp *repo.Repository, name, file string) (string, map[string]json.RawMessage, error) {
	for _, ttl := range []time.Duration{rp.Cfg.Proxy.MetadataTTL(), 0} {
		pk, err := h.proxyPackument(ctx, rp, name, ttl)
		if err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				return "", nil, proxy.ErrUpstreamNotFound
			}
			return "", nil, err
		}
		for v, man := range pk.Versions {
			if tarballFile(name, v, man) == file {
				return v, man, nil
			}
		}
	}
	return "", nil, proxy.ErrUpstreamNotFound
}

// componentAttrs extracts searchable attributes from a version manifest.
func componentAttrs(man map[string]json.RawMessage) json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, k := range []string{"description", "license", "keywords", "author", "homepage", "repository"} {
		if v, ok := man[k]; ok && len(v) < 16<<10 {
			out[k] = v
		}
	}
	return marshal(out)
}

var errIntegrity = errors.New("upstream tarball does not match its published integrity")

// verifying wraps body so that reading to EOF fails when the content does
// not match the published integrity (sha512 preferred) or shasum.
func verifying(body io.ReadCloser, integrity, shasum string) (io.ReadCloser, error) {
	for _, part := range strings.Fields(integrity) {
		alg, b64, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		want, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		switch alg {
		case "sha512":
			return &verifyReader{ReadCloser: body, h: sha512.New(), want: want}, nil
		case "sha256":
			return &verifyReader{ReadCloser: body, h: sha256.New(), want: want}, nil
		}
	}
	if shasum != "" {
		want, err := hex.DecodeString(shasum)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream shasum %q", shasum)
		}
		return &verifyReader{ReadCloser: body, h: sha1.New(), want: want}, nil //nolint:gosec
	}
	return body, nil
}

type verifyReader struct {
	io.ReadCloser
	h    hash.Hash
	want []byte
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.ReadCloser.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) && string(v.h.Sum(nil)) != string(v.want) {
		return n, errIntegrity
	}
	return n, err
}
