package helm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/proxy"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/store"
)

var (
	timeZero time.Time

	_ format.RootMounter = (*Handler)(nil)
)

// api serves the ChartMuseum-compatible API below api/.
func (h *Handler) api(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	segs := strings.Split(p, "/")
	switch {
	case p == "charts" && r.Method == http.MethodPost, p == "prov" && r.Method == http.MethodPost:
		if !rp.IsHosted() {
			jsonError(w, http.StatusMethodNotAllowed, "uploads are only accepted by hosted repositories")
			return
		}
		if !h.env.Authorize(w, r, rp, authz.Write) {
			return
		}
		h.apiUpload(w, r, rp, p == "prov")
	case segs[0] == "charts" && len(segs) <= 3 && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		if !h.env.Authorize(w, r, rp, authz.Read) {
			return
		}
		h.apiList(w, r, rp, segs[1:])
	case segs[0] == "charts" && len(segs) == 3 && r.Method == http.MethodDelete:
		if !h.deletable(w, r, rp) {
			return
		}
		h.apiDelete(w, r, rp, segs[1], segs[2])
	case segs[0] == "charts" || segs[0] == "prov":
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		jsonError(w, http.StatusNotFound, "not found")
	}
}

func (h *Handler) apiUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository, provOnly bool) {
	ctx := r.Context()
	actor := format.Actor(r)
	var chart, prov []byte
	provName := ""
	if ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); strings.HasPrefix(ct, "multipart/") {
		mr := multipart.NewReader(format.LimitedBody(w, r, 2*MaxChart), params["boundary"])
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				jsonError(w, http.StatusBadRequest, "invalid multipart body: "+err.Error())
				return
			}
			b, err := io.ReadAll(io.LimitReader(part, MaxChart+1))
			if err != nil || len(b) > MaxChart {
				jsonError(w, http.StatusBadRequest, "upload too large or interrupted")
				return
			}
			switch part.FormName() {
			case "chart":
				chart = b
			case "prov":
				prov, provName = b, part.FileName()
			}
		}
	} else {
		b, err := io.ReadAll(format.LimitedBody(w, r, MaxChart))
		if err != nil {
			jsonError(w, http.StatusBadRequest, "upload too large or interrupted: "+err.Error())
			return
		}
		if provOnly {
			prov = b
		} else {
			chart = b
		}
	}
	if provOnly {
		chart = nil
	}
	if chart == nil && prov == nil {
		jsonError(w, http.StatusBadRequest, `no chart or provenance file in the request (multipart fields "chart" and "prov")`)
		return
	}
	if chart != nil {
		_, meta, err := h.storeChart(ctx, rp, chart, actor)
		if err != nil {
			h.apiFail(w, r, err)
			return
		}
		// A provenance file sent with the chart belongs to it.
		provName = chartFile(meta.Name, meta.Version) + ".prov"
	}
	if prov != nil {
		if _, err := h.storeProv(ctx, rp, prov, provName, actor); err != nil {
			h.apiFail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"saved": true})
}

// apiList answers api/charts, api/charts/{name} and api/charts/{name}/{version}.
func (h *Handler) apiList(w http.ResponseWriter, r *http.Request, rp *repo.Repository, segs []string) {
	ix, err := h.index(r.Context(), rp, 0)
	if err != nil {
		h.apiFail(w, r, err)
		return
	}
	switch len(segs) {
	case 0:
		out := map[string][]map[string]any{}
		for name, vs := range ix.entries {
			for _, cv := range vs {
				out[name] = append(out[name], cv.entry())
			}
		}
		writeJSON(w, http.StatusOK, out)
	case 1:
		vs := ix.entries[segs[0]]
		if len(vs) == 0 {
			jsonError(w, http.StatusNotFound, "chart not found")
			return
		}
		out := make([]map[string]any, 0, len(vs))
		for _, cv := range vs {
			out = append(out, cv.entry())
		}
		writeJSON(w, http.StatusOK, out)
	default:
		vs := ix.entries[segs[0]]
		var cv *chartVersion
		if segs[1] == "latest" && len(vs) > 0 {
			cv = vs[0]
		} else {
			cv = ix.find(segs[0], segs[1])
		}
		if cv == nil {
			jsonError(w, http.StatusNotFound, "chart version not found")
			return
		}
		writeJSON(w, http.StatusOK, cv.entry())
	}
}

func (h *Handler) apiDelete(w http.ResponseWriter, r *http.Request, rp *repo.Repository, name, version string) {
	ctx := r.Context()
	c, err := h.env.Repos.Store.FindComponent(ctx, rp.ID, name, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "chart version not found")
			return
		}
		h.apiFail(w, r, err)
		return
	}
	as, err := h.env.Repos.Store.ListComponentAssets(ctx, c.ID)
	if err != nil {
		h.apiFail(w, r, err)
		return
	}
	for _, a := range as {
		if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
			h.apiFail(w, r, err)
			return
		}
	}
	if err := h.AfterDelete(ctx, rp, as); err != nil {
		h.env.Logger.Warn("helm: after delete", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *Handler) apiFail(w http.ResponseWriter, r *http.Request, err error) {
	var ce format.ClientError
	var ue *proxy.UpstreamError
	switch {
	case errors.As(err, &ce):
		jsonError(w, http.StatusBadRequest, ce.Msg)
	case errors.Is(err, repo.ErrRedeploy):
		jsonError(w, http.StatusConflict, "file already exists (redeploy is disabled for this repository)")
	case errors.Is(err, repo.ErrNotFound), errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "not found")
	case errors.As(err, &ue):
		jsonError(w, http.StatusBadGateway, "bad gateway: "+err.Error())
	default:
		h.env.WriteError(w, r, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	httpx.WriteJSON(w, status, v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// verifying fails the read at EOF when the content's sha256 differs from
// the digest published in the upstream index.
func verifying(body io.ReadCloser, wantHex string) io.ReadCloser {
	return &verifyReader{ReadCloser: body, h: sha256.New(), want: strings.ToLower(wantHex)}
}

var errDigest = errors.New("upstream chart does not match the digest in its index")

type verifyReader struct {
	io.ReadCloser
	h    hash.Hash
	want string
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.ReadCloser.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) && hex.EncodeToString(v.h.Sum(nil)) != v.want {
		return n, errDigest
	}
	return n, err
}

// Mount serves the ChartMuseum multi-tenant API layout
// /api/repository/{repo}/charts, which is what `helm cm-push` uses for a
// repository URL with a path unless --context-path is given.
func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.env.Auth.Middleware(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Entrepot"`)
			jsonError(w, http.StatusUnauthorized, "invalid credentials")
		}))
		r.HandleFunc("/api/repository/{repo}/*", func(w http.ResponseWriter, r *http.Request) {
			rp, err := h.env.Repos.Get(r.Context(), chi.URLParam(r, "repo"))
			if err != nil || rp.Format != h.Name() {
				jsonError(w, http.StatusNotFound, "repository not found")
				return
			}
			rest := strings.Trim(chi.URLParam(r, "*"), "/")
			if rest != "charts" && rest != "prov" && !strings.HasPrefix(rest, "charts/") {
				jsonError(w, http.StatusNotFound, "not found")
				return
			}
			h.api(w, r, rp, rest)
		})
	})
}
