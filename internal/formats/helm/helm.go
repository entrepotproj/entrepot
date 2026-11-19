// Package helm implements Helm chart repositories (hosted, proxy, group).
//
// URL layout below /repository/{repo}/:
//
//	GET    index.yaml                        repository index (chart URLs are
//	                                         relative: charts/{name}-{version}.tgz)
//	GET    charts/{name}-{version}.tgz       chart package (also at the root)
//	GET    charts/{name}-{version}.tgz.prov  provenance file
//	PUT    charts/{name}-{version}.tgz       upload a package (hosted; also at the root)
//	PUT    charts/{name}-{version}.tgz.prov  upload a provenance file
//	DELETE charts/{file}                     delete a package (and its .prov)
//
// ChartMuseum-compatible API (used by the helm cm-push plugin and curl):
//
//	POST   api/charts                        upload: raw body, or multipart
//	                                         fields "chart" and optional "prov"
//	POST   api/prov                          upload a provenance file
//	GET    api/charts                        all charts (JSON)
//	GET    api/charts/{name}                 versions of a chart
//	GET    api/charts/{name}/{version}       one version ("latest" allowed)
//	DELETE api/charts/{name}/{version}       delete a version
//
// The same API is also served at /api/repository/{repo}/charts..., the
// multi-tenant ChartMuseum layout `helm cm-push` uses by default for a
// repository URL with a path (alternatively pass
// --context-path /repository/{repo}).
//
// Hosted repositories store packages at charts/{name}-{version}.tgz with the
// Chart.yaml metadata in the asset attributes; index.yaml is generated from
// them on request (cached per content fingerprint), so deletions through
// any path are reflected immediately. Proxy repositories cache the upstream
// index.yaml (metadata TTL) and rewrite every version's URL to
// charts/{name}-{version}.tgz, remembering the upstream URL (which may be
// relative to the index or absolute on another host); packages are cached
// immutably and verified against the index digest. Group repositories merge
// member indexes (first member wins per name and version; with preferHosted,
// chart names present in a hosted member are not taken from proxies) and
// serve packages from the member that contributed the version.
//
// OCI-based Helm charts (helm push oci://...) are served by Docker
// repositories.
package helm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

// MaxChart is the largest accepted chart package.
const MaxChart = 128 << 20

type Handler struct {
	env *format.Env

	sf       singleflight.Group
	mu       sync.Mutex
	parsed   map[string]parsedIndex   // proxy repo ID -> parsed upstream index
	rendered map[string]renderedIndex // repo ID -> rendered index.yaml
}

type parsedIndex struct {
	key string
	ix  *chartIndex
}

type renderedIndex struct {
	fingerprint string
	body        []byte
}

var (
	_ format.Uploader   = (*Handler)(nil)
	_ format.DeleteHook = (*Handler)(nil)
	_ format.Validator  = (*Handler)(nil)
)

func New(env *format.Env) *Handler {
	return &Handler{env: env, parsed: map[string]parsedIndex{}, rendered: map[string]renderedIndex{}}
}

func (h *Handler) Name() string    { return "helm" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

// ValidateRepository checks proxy configuration.
func (h *Handler) ValidateRepository(kind string, cfg repo.Config) error {
	if kind == repo.KindProxy && cfg.Proxy != nil {
		u, err := url.Parse(cfg.Proxy.RemoteURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return format.BadRequest("proxy.remoteUrl must be an http(s) URL, e.g. https://charts.bitnami.com/bitnami")
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	unescaped, err := url.PathUnescape(p)
	if err != nil {
		http.Error(w, "invalid path encoding", http.StatusBadRequest)
		return
	}
	clean, err := format.CleanPath(unescaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clean = strings.TrimSuffix(clean, "/")
	if clean == "api" || strings.HasPrefix(clean, "api/") {
		h.api(w, r, rp, strings.TrimPrefix(strings.TrimPrefix(clean, "api"), "/"))
		return
	}
	file, isFile := packagePath(clean)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.env.Authorize(w, r, rp, authz.Read) {
			return
		}
		switch {
		case clean == "":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "Entrepot Helm chart repository "+rp.Name+".\n\n"+
				"  helm repo add "+rp.Name+" "+h.repoURL(r, rp)+"\n")
		case clean == indexPath || clean == "index.yml":
			h.getIndex(w, r, rp)
		case isFile:
			h.download(w, r, rp, file)
		default:
			http.NotFound(w, r)
		}
	case http.MethodPut:
		if !isFile {
			http.Error(w, "upload to charts/{name}-{version}.tgz (or .tgz.prov)", http.StatusBadRequest)
			return
		}
		if !h.writable(w, r, rp) {
			return
		}
		body, err := io.ReadAll(format.LimitedBody(w, r, MaxChart))
		if err != nil {
			http.Error(w, "upload too large or interrupted: "+err.Error(), http.StatusBadRequest)
			return
		}
		var a *store.Asset
		if strings.HasSuffix(file, ".prov") {
			a, err = h.storeProv(r.Context(), rp, body, file, format.Actor(r))
		} else {
			var meta *chartMeta
			a, meta, err = h.storeChart(r.Context(), rp, body, format.Actor(r))
			if err == nil && chartFile(meta.Name, meta.Version) != file {
				h.env.Logger.Info("helm: stored chart under its canonical name", "repository", rp.Name,
					"requested", file, "stored", a.Path)
			}
		}
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		w.Header().Set("ETag", `"`+a.Digest+`"`)
		w.Header().Set("Location", h.repoURL(r, rp)+a.Path)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if !isFile {
			http.Error(w, "only charts/{file} can be deleted", http.StatusBadRequest)
			return
		}
		if !h.deletable(w, r, rp) {
			return
		}
		a, err := h.env.Repos.GetAsset(r.Context(), rp, chartsDir+file)
		if err == nil {
			_, err = h.env.Repos.Delete(r.Context(), a.ID)
		}
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if err := h.AfterDelete(r.Context(), rp, []*store.Asset{a}); err != nil {
			h.env.Logger.Warn("helm: after delete", "err", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// packagePath maps charts/{file} or a root {file} to the package file name.
func packagePath(p string) (string, bool) {
	file := strings.TrimPrefix(p, chartsDir)
	if file == "" || strings.Contains(file, "/") {
		return "", false
	}
	if !strings.HasSuffix(file, ".tgz") && !strings.HasSuffix(file, ".tgz.prov") {
		return "", false
	}
	return file, true
}

func (h *Handler) repoURL(r *http.Request, rp *repo.Repository) string {
	return h.env.URLs.BaseURL(r) + "/repository/" + url.PathEscape(rp.Name) + "/"
}

func (h *Handler) writable(w http.ResponseWriter, r *http.Request, rp *repo.Repository) bool {
	if !rp.IsHosted() {
		http.Error(w, "uploads are only accepted by hosted repositories", http.StatusMethodNotAllowed)
		return false
	}
	return h.env.Authorize(w, r, rp, authz.Write)
}

func (h *Handler) deletable(w http.ResponseWriter, r *http.Request, rp *repo.Repository) bool {
	if rp.IsGroup() {
		http.Error(w, "group repositories are read-only", http.StatusMethodNotAllowed)
		return false
	}
	return h.env.Authorize(w, r, rp, authz.Delete)
}

func (h *Handler) getIndex(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	body, fp, err := h.renderedIndex(r.Context(), rp)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	etag := `"` + fp + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	http.ServeContent(w, r, "", timeZero, bytes.NewReader(body))
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request, rp *repo.Repository, file string) {
	owner, a, err := h.findPackage(r.Context(), rp, file, 0)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	ct := "application/gzip"
	if strings.HasSuffix(file, ".prov") {
		ct = "application/pgp-signature"
	}
	h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{ContentType: ct})
}

// findPackage locates a package or provenance file.
func (h *Handler) findPackage(ctx context.Context, rp *repo.Repository, file string, depth int) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		a, err := h.proxyPackage(ctx, rp, file)
		return rp, a, err
	case repo.KindGroup:
		ix, err := h.groupIndex(ctx, rp, depth)
		if err != nil {
			return nil, nil, err
		}
		cv := ix.byFile[strings.TrimSuffix(file, ".prov")]
		if cv == nil || cv.owner == nil {
			return nil, nil, repo.ErrNotFound
		}
		return h.findPackage(ctx, cv.owner, file, depth+1)
	default:
		a, err := h.env.Repos.GetAsset(ctx, rp, chartsDir+file)
		return rp, a, err
	}
}

// upstreamChart finds a chart on the cached upstream index, revalidating
// it once when the chart is not listed (a new release).
func (h *Handler) upstreamChart(ctx context.Context, rp *repo.Repository, file string) (*chartVersion, error) {
	for _, t := range []time.Duration{rp.Cfg.Proxy.MetadataTTL(), 0} {
		ix, err := h.proxyIndex(ctx, rp, t)
		if err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				return nil, proxy.ErrUpstreamNotFound
			}
			return nil, err
		}
		if cv := ix.byFile[file]; cv != nil {
			return cv, nil
		}
	}
	return nil, proxy.ErrUpstreamNotFound
}

func (h *Handler) proxyPackage(ctx context.Context, rp *repo.Repository, file string) (*store.Asset, error) {
	chart := strings.TrimSuffix(file, ".prov")
	prov := chart != file
	return h.env.Proxy.Get(ctx, rp, chartsDir+file, rp.Cfg.Proxy.ContentTTL(), func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
		cv, err := h.upstreamChart(ctx, rp, chart)
		if err != nil {
			return nil, err
		}
		target := cv.Upstream
		if prov {
			target += ".prov"
		}
		res, err := h.env.Proxy.FetchURL(ctx, rp, target, existing, nil)
		if err != nil || res.NotModified {
			return res, err
		}
		meta := metaFromMap(cv)
		attrs := map[string]any{"upstreamUrl": target}
		if !prov {
			attrs["chart"] = meta
			if cv.Digest != "" {
				res.Body = verifying(res.Body, cv.Digest)
			}
			res.ContentType = "application/gzip"
		} else {
			res.ContentType = "application/pgp-signature"
		}
		res.Attrs = attrs
		compAttrs, _ := json.Marshal(componentAttrs(meta))
		res.Component = &repo.ComponentRef{Name: cv.Name, Version: cv.Version, Attrs: compAttrs}
		return res, nil
	})
}

// metaFromMap converts an index entry's metadata to chartMeta (best effort).
func metaFromMap(cv *chartVersion) *chartMeta {
	var m chartMeta
	b, _ := json.Marshal(cv.entry())
	_ = json.Unmarshal(b, &m)
	m.Name, m.Version = cv.Name, cv.Version
	return &m
}

// componentAttrs are the searchable attributes recorded on components.
func componentAttrs(m *chartMeta) map[string]any {
	out := map[string]any{"apiVersion": m.APIVersion}
	if m.Description != "" {
		out["description"] = m.Description
	}
	if m.AppVersion != "" {
		out["appVersion"] = m.AppVersion
	}
	if m.Type != "" {
		out["type"] = m.Type
	}
	if m.Home != "" {
		out["home"] = m.Home
	}
	if len(m.Keywords) > 0 {
		out["keywords"] = m.Keywords
	}
	if m.Deprecated {
		out["deprecated"] = true
	}
	return out
}

// ---- storing ----

func (h *Handler) storeChart(ctx context.Context, rp *repo.Repository, body []byte, actor string) (*store.Asset, *chartMeta, error) {
	meta, err := parseChart(body)
	if err != nil {
		return nil, nil, err
	}
	attrs, _ := json.Marshal(assetAttrs{Chart: meta})
	compAttrs, _ := json.Marshal(componentAttrs(meta))
	a, err := h.env.Repos.PutBytes(ctx, rp, body, repo.PutOptions{
		Path:        chartsDir + chartFile(meta.Name, meta.Version),
		ContentType: "application/gzip",
		Attrs:       attrs,
		CreatedBy:   actor,
		Component:   &repo.ComponentRef{Name: meta.Name, Version: meta.Version, Attrs: compAttrs},
		NoOverwrite: !rp.AllowRedeploy(),
	})
	return a, meta, err
}

// storeProv stores a provenance file next to its chart. file is the
// requested name ({chart}.tgz.prov) or empty to derive it from the content.
func (h *Handler) storeProv(ctx context.Context, rp *repo.Repository, body []byte, file, actor string) (*store.Asset, error) {
	chart := strings.TrimSuffix(file, ".prov")
	if chart == "" || !strings.HasSuffix(chart, ".tgz") {
		chart = provChartFile(body)
	}
	if chart == "" || strings.Contains(chart, "/") {
		return nil, format.BadRequest("cannot determine the chart of this provenance file")
	}
	if !bytes.Contains(body, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		return nil, format.BadRequest("not a provenance file (expected a PGP signed message)")
	}
	o := repo.PutOptions{
		Path:        chartsDir + chart + ".prov",
		ContentType: "application/pgp-signature",
		CreatedBy:   actor,
		NoOverwrite: !rp.AllowRedeploy(),
	}
	// Attach the provenance file to the chart's component so deleting the
	// chart version removes both.
	if ca, err := h.env.Repos.GetAsset(ctx, rp, chartsDir+chart); err == nil {
		var attrs assetAttrs
		if json.Unmarshal(ca.Attrs, &attrs) == nil && attrs.Chart != nil {
			o.Component = &repo.ComponentRef{Name: attrs.Chart.Name, Version: attrs.Chart.Version}
		}
	}
	return h.env.Repos.PutBytes(ctx, rp, body, o)
}

// AfterDelete removes provenance files whose chart package was deleted.
func (h *Handler) AfterDelete(ctx context.Context, rp *repo.Repository, deleted []*store.Asset) error {
	gone := map[string]bool{}
	for _, a := range deleted {
		gone[a.Path] = true
	}
	for _, a := range deleted {
		if !strings.HasPrefix(a.Path, chartsDir) || !strings.HasSuffix(a.Path, ".tgz") || gone[a.Path+".prov"] {
			continue
		}
		prov, err := h.env.Repos.GetAsset(ctx, rp, a.Path+".prov")
		if errors.Is(err, repo.ErrNotFound) {
			continue
		}
		if err == nil {
			_, err = h.env.Repos.Delete(ctx, prov.ID)
		}
		if err != nil && !errors.Is(err, repo.ErrNotFound) {
			return err
		}
	}
	return nil
}

// Upload implements the generic upload API: a chart package, or a
// provenance file (*.prov).
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, format.BadRequest("uploads require a hosted repository")
	}
	body, err := io.ReadAll(io.LimitReader(u.File, MaxChart+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxChart {
		return nil, format.BadRequest("chart package is too large")
	}
	if strings.HasSuffix(u.Header.Filename, ".prov") {
		a, err := h.storeProv(ctx, rp, body, u.Header.Filename, u.Uploader.Name)
		if err != nil {
			return nil, err
		}
		return []*store.Asset{a}, nil
	}
	a, _, err := h.storeChart(ctx, rp, body, u.Uploader.Name)
	if err != nil {
		return nil, err
	}
	return []*store.Asset{a}, nil
}
