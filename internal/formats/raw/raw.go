// Package raw implements generic file repositories.
//
//	GET    /repository/{repo}/{path}   download (directory listing for dirs)
//	HEAD   /repository/{repo}/{path}
//	PUT    /repository/{repo}/{path}   upload (hosted)
//	DELETE /repository/{repo}/{path}   delete a file, or a directory ending in /
//
// Proxy repositories fetch {remoteUrl}/{path} on demand and cache it.
// Group repositories return the first member that has the file.
package raw

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/entrepotproj/entrepot/internal/authz"
	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/proxy"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

// MaxUpload is the largest accepted raw upload (10 GiB).
const MaxUpload = 10 << 30

type Handler struct {
	env *format.Env
}

func New(env *format.Env) *Handler { return &Handler{env: env} }

func (h *Handler) Name() string    { return "raw" }
func (h *Handler) Kinds() []string { return []string{repo.KindHosted, repo.KindProxy, repo.KindGroup} }

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
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.env.Authorize(w, r, rp, authz.Read) {
			return
		}
		h.get(w, r, rp, clean)
	case http.MethodPut:
		if !rp.IsHosted() {
			http.Error(w, "uploads are only accepted by hosted repositories", http.StatusMethodNotAllowed)
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Write) {
			return
		}
		h.put(w, r, rp, clean)
	case http.MethodDelete:
		if !h.env.Authorize(w, r, rp, authz.Delete) {
			return
		}
		h.delete(w, r, rp, clean)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	if p == "" || strings.HasSuffix(p, "/") {
		h.listing(w, r, rp, p)
		return
	}
	owner, a, err := h.find(ctx, rp, p)
	if errors.Is(err, repo.ErrNotFound) {
		// Maybe a directory without trailing slash.
		if entries, _ := h.env.Repos.Store.Browse(ctx, rp.ID, p+"/", 1); len(entries) > 0 {
			http.Redirect(w, r, path.Base(p)+"/", http.StatusMovedPermanently)
			return
		}
	}
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{})
}

// find locates the asset, consulting upstreams (proxy) or members (group).
func (h *Handler) find(ctx context.Context, rp *repo.Repository, p string) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		ttl := rp.Cfg.Proxy.ContentTTL()
		if rp.Cfg.Proxy.ContentTTLSeconds == 0 {
			// Raw files are not versioned, so revalidate on the metadata TTL.
			ttl = rp.Cfg.Proxy.MetadataTTL()
		}
		a, err := h.env.Proxy.Get(ctx, rp, p, ttl, func(ctx context.Context, existing *store.Asset) (*proxy.FetchResult, error) {
			res, err := h.env.Proxy.FetchURL(ctx, rp, proxy.JoinURL(rp.Cfg.Proxy.RemoteURL, p), existing, nil)
			if err == nil && !res.NotModified && (res.ContentType == "" || res.ContentType == "application/octet-stream") {
				res.ContentType = contentType(p)
			}
			if err == nil {
				res.Component = Component(rp, p)
			}
			return res, err
		})
		return rp, a, err
	case repo.KindGroup:
		for _, m := range h.env.Members(ctx, rp) {
			owner, a, err := h.find(ctx, m, p)
			if err == nil {
				return owner, a, nil
			}
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "err", err)
			}
		}
		return nil, nil, repo.ErrNotFound
	default:
		a, err := h.env.Repos.GetAsset(ctx, rp, p)
		return rp, a, err
	}
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	if p == "" || strings.HasSuffix(p, "/") {
		http.Error(w, "a file path is required", http.StatusBadRequest)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" || ct == "application/x-www-form-urlencoded" {
		ct = contentType(p)
	}
	a, err := h.env.Repos.Put(r.Context(), rp, repo.PutOptions{
		Path:        p,
		Body:        format.LimitedBody(w, r, MaxUpload),
		ContentType: ct,
		CreatedBy:   format.Actor(r),
		NoOverwrite: !rp.AllowRedeploy(),
		Component:   Component(rp, p),
	})
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+a.Digest+`"`)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	if p == "" {
		http.Error(w, "refusing to delete the repository root", http.StatusBadRequest)
		return
	}
	if strings.HasSuffix(p, "/") {
		n, err := h.env.Repos.Store.DeleteAssetsByPrefix(ctx, rp.ID, p)
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		if n == 0 {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
	w.WriteHeader(http.StatusNoContent)
}

var listingTmpl = template.Must(template.New("l").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Index of /{{.Repo}}/{{.Dir}}</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem}td{padding:.15rem 1rem .15rem 0}a{text-decoration:none}</style></head>
<body><h1>Index of /{{.Repo}}/{{.Dir}}</h1><table>
{{if .Dir}}<tr><td><a href="../">../</a></td><td></td></tr>{{end}}
{{range .Entries}}<tr><td><a href="{{.Name}}{{if .IsDir}}/{{end}}">{{.Name}}{{if .IsDir}}/{{end}}</a></td><td>{{if not .IsDir}}{{.Size}}{{end}}</td></tr>
{{end}}</table></body></html>`))

func (h *Handler) listing(w http.ResponseWriter, r *http.Request, rp *repo.Repository, dir string) {
	ctx := r.Context()
	repos := []*repo.Repository{rp}
	if rp.IsGroup() {
		repos = h.env.Members(ctx, rp)
	}
	seen := map[string]bool{}
	var entries []store.BrowseEntry
	for _, x := range repos {
		es, err := h.env.Repos.Store.Browse(ctx, x.ID, dir, 5000)
		if err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		for _, e := range es {
			if !seen[e.Path] {
				seen[e.Path] = true
				entries = append(entries, e)
			}
		}
	}
	if len(entries) == 0 && dir != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = listingTmpl.Execute(w, map[string]any{"Repo": rp.Name, "Dir": dir, "Entries": entries})
}

// Upload implements the generic upload API.
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, fmt.Errorf("%w: uploads require a hosted repository", format.ErrBadPath)
	}
	p := u.Fields["path"]
	if p == "" {
		p = u.Header.Filename
	} else if strings.HasSuffix(p, "/") {
		p += u.Header.Filename
	}
	clean, err := format.CleanPath(p)
	if err != nil || clean == "" || strings.HasSuffix(clean, "/") {
		return nil, format.ErrBadPath
	}
	ct := u.Header.Header.Get("Content-Type")
	if ct == "" || ct == "application/octet-stream" {
		ct = contentType(clean)
	}
	a, err := h.env.Repos.Put(ctx, rp, repo.PutOptions{
		Path:        clean,
		Body:        u.File,
		ContentType: ct,
		CreatedBy:   u.Uploader.Name,
		NoOverwrite: !rp.AllowRedeploy(),
		Component:   Component(rp, clean),
	})
	if err != nil {
		return nil, err
	}
	return []*store.Asset{a}, nil
}

// Component is the component of a raw file: in repositories with scanning
// enabled each file is one, named after its path (no version), so it can be
// scanned and gated like a package. Elsewhere raw files have none.
func Component(rp *repo.Repository, p string) *repo.ComponentRef {
	if !rp.Cfg.Scan.Enabled() {
		return nil
	}
	return &repo.ComponentRef{Name: p}
}

func contentType(p string) string {
	if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
