package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
)

// maxDepth bounds group nesting.
const maxDepth = 4

// ---- manifests -------------------------------------------------------------

type descriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls,omitempty"`
}

type manifestDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
	Subject       *descriptor  `json:"subject"`
	// schema1
	FSLayers []json.RawMessage `json:"fsLayers"`
}

func isIndex(mt string) bool { return mt == MediaOCIIndex || mt == MediaDockerManifestList }
func isImage(mt string) bool { return mt == MediaOCIManifest || mt == MediaDockerManifest }

// mediaTypeOf determines a manifest's media type from the Content-Type and
// the document itself.
func mediaTypeOf(contentType string, doc *manifestDoc) (string, error) {
	ct, _, _ := mime.ParseMediaType(contentType)
	switch ct {
	case "", "application/json", "application/octet-stream", "text/plain":
		ct = ""
	}
	if ct != "" && doc.MediaType != "" && ct != doc.MediaType {
		return "", fmt.Errorf("Content-Type %s does not match the manifest mediaType %s", ct, doc.MediaType)
	}
	mt := ct
	if mt == "" {
		mt = doc.MediaType
	}
	if mt == "" {
		switch {
		case doc.Manifests != nil:
			mt = MediaOCIIndex
		case doc.Config != nil:
			mt = MediaOCIManifest
		case doc.FSLayers != nil:
			mt = MediaDockerSchema1
		}
	}
	return mt, nil
}

// parseRef returns the digest (if ref is one) or validates ref as a tag.
func parseRef(ref string) (d storage.Digest, tag string, err error) {
	if strings.Contains(ref, ":") {
		d, err = storage.ParseDigest(ref)
		return d, "", err
	}
	if !tagRE.MatchString(ref) {
		return "", "", errors.New("invalid tag " + ref)
	}
	return "", ref, nil
}

func (h *Handler) manifests(w http.ResponseWriter, r *http.Request, q *request, ref string) {
	d, tag, err := parseRef(ref)
	if err != nil {
		code := codeManifestInvalid
		if tag == "" && strings.Contains(ref, ":") {
			code = codeDigestInvalid
		}
		writeErr(w, http.StatusBadRequest, code, err.Error())
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.authorize(w, r, q, pull) {
			return
		}
		owner, a, err := h.findManifest(r.Context(), q.rp, q.image, d, tag, 0)
		if err != nil {
			h.fail(w, r, err, codeManifestUnknown)
			return
		}
		w.Header().Set("Docker-Content-Digest", a.Digest)
		h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{NoRedirect: true})
	case http.MethodPut:
		if !h.authorize(w, r, q, push) || !h.hostedOnly(w, q) {
			return
		}
		h.putManifest(w, r, q, d, tag)
	case http.MethodDelete:
		if !h.authorize(w, r, q, del) || !h.hostedOnly(w, q) {
			return
		}
		h.deleteManifest(w, r, q, d, tag)
	default:
		writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
	}
}

func (h *Handler) hostedOnly(w http.ResponseWriter, q *request) bool {
	if q.rp.IsHosted() {
		return true
	}
	writeErr(w, http.StatusMethodNotAllowed, codeUnsupported,
		fmt.Sprintf("%s is a %s repository; push to a hosted docker repository", q.rp.Name, q.rp.Kind))
	return false
}

func (h *Handler) putManifest(w http.ResponseWriter, r *http.Request, q *request, want storage.Digest, tag string) {
	ctx := r.Context()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxManifest))
	if err != nil {
		h.fail(w, r, err, codeManifestInvalid)
		return
	}
	d := storage.DigestBytes(body)
	if want != "" && want != d {
		writeErr(w, http.StatusBadRequest, codeDigestInvalid,
			fmt.Sprintf("manifest digest %s does not match %s", d, want))
		return
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		writeErr(w, http.StatusBadRequest, codeManifestInvalid, "manifest is not valid JSON: "+err.Error())
		return
	}
	mt, err := mediaTypeOf(r.Header.Get("Content-Type"), &doc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeManifestInvalid, err.Error())
		return
	}
	switch {
	case mt == MediaDockerSchema1 || mt == MediaDockerSchema1JWS:
		writeErr(w, http.StatusBadRequest, codeManifestInvalid, "Docker schema1 manifests are not supported")
		return
	case !isImage(mt) && !isIndex(mt):
		writeErr(w, http.StatusBadRequest, codeManifestInvalid, "unsupported manifest media type "+strconv.Quote(mt))
		return
	case doc.SchemaVersion != 2:
		writeErr(w, http.StatusBadRequest, codeManifestInvalid, "schemaVersion must be 2")
		return
	}
	// Referenced content must already be in this image.
	if isImage(mt) {
		if doc.Config == nil {
			writeErr(w, http.StatusBadRequest, codeManifestInvalid, "image manifest has no config")
			return
		}
		refs := append([]descriptor{*doc.Config}, doc.Layers...)
		for _, ds := range refs {
			if len(ds.URLs) > 0 || strings.Contains(ds.MediaType, "foreign") || strings.Contains(ds.MediaType, "nondistributable") {
				continue
			}
			bd, err := storage.ParseDigest(ds.Digest)
			if err != nil {
				writeErr(w, http.StatusBadRequest, codeManifestInvalid, "invalid descriptor digest "+strconv.Quote(ds.Digest))
				return
			}
			a, err := h.env.Repos.GetAsset(ctx, q.rp, blobPath(q.image, bd))
			if errors.Is(err, repo.ErrNotFound) {
				writeErr(w, http.StatusBadRequest, codeManifestBlobUnknown, "blob unknown to registry: "+ds.Digest,
					map[string]string{"digest": ds.Digest})
				return
			}
			if err != nil {
				h.fail(w, r, err, codeBlobUnknown)
				return
			}
			if ds.Size > 0 && a.Size != ds.Size {
				writeErr(w, http.StatusBadRequest, codeManifestInvalid,
					fmt.Sprintf("descriptor size %d of %s does not match the stored size %d", ds.Size, ds.Digest, a.Size))
				return
			}
		}
	} else {
		for _, ds := range doc.Manifests {
			md, err := storage.ParseDigest(ds.Digest)
			if err != nil {
				writeErr(w, http.StatusBadRequest, codeManifestInvalid, "invalid descriptor digest "+strconv.Quote(ds.Digest))
				return
			}
			_, err = h.env.Repos.GetAsset(ctx, q.rp, manifestPath(q.image, md))
			if errors.Is(err, repo.ErrNotFound) {
				// Indexes may also reference plain blobs (artifacts).
				_, err = h.env.Repos.GetAsset(ctx, q.rp, blobPath(q.image, md))
			}
			if errors.Is(err, repo.ErrNotFound) {
				writeErr(w, http.StatusBadRequest, codeManifestBlobUnknown, "manifest unknown to registry: "+ds.Digest,
					map[string]string{"digest": ds.Digest})
				return
			}
			if err != nil {
				h.fail(w, r, err, codeManifestUnknown)
				return
			}
		}
	}

	attrs := map[string]any{"mediaType": mt}
	if doc.ArtifactType != "" {
		attrs["artifactType"] = doc.ArtifactType
	}
	if doc.Subject != nil {
		attrs["subject"] = doc.Subject.Digest
	}
	rawAttrs, _ := json.Marshal(attrs)
	a, err := h.env.Repos.Put(ctx, q.rp, repo.PutOptions{
		Path:           manifestPath(q.image, d),
		Body:           bytes.NewReader(body),
		ContentType:    mt,
		ExpectedDigest: d,
		Attrs:          rawAttrs,
		CreatedBy:      format.Actor(r),
	})
	if err != nil {
		h.fail(w, r, err, codeManifestUnknown)
		return
	}
	if tag != "" {
		attrs["digest"] = d.String()
		tagAttrs, _ := json.Marshal(attrs)
		_, err := h.env.Repos.PutStored(ctx, q.rp, d, a.Size, repo.PutOptions{
			Path:        tagPath(q.image, tag),
			ContentType: mt,
			Attrs:       tagAttrs,
			CreatedBy:   format.Actor(r),
			Component:   &repo.ComponentRef{Name: q.image, Version: tag, Attrs: tagAttrs},
			NoOverwrite: !q.rp.AllowRedeploy(),
		})
		if errors.Is(err, repo.ErrRedeploy) {
			writeErr(w, http.StatusConflict, codeDenied, fmt.Sprintf(
				"tag %s:%s already exists with different content and redeploy is disabled for repository %s",
				q.client, tag, q.rp.Name))
			return
		}
		if err != nil {
			h.fail(w, r, err, codeManifestUnknown)
			return
		}
	}
	w.Header().Set("Docker-Content-Digest", d.String())
	w.Header().Set("Location", q.base()+"/manifests/"+d.String())
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) deleteManifest(w http.ResponseWriter, r *http.Request, q *request, d storage.Digest, tag string) {
	ctx := r.Context()
	if tag != "" {
		a, err := h.env.Repos.GetAsset(ctx, q.rp, tagPath(q.image, tag))
		if err == nil {
			_, err = h.env.Repos.Delete(ctx, a.ID)
		}
		if err != nil {
			h.fail(w, r, err, codeManifestUnknown)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	a, err := h.env.Repos.GetAsset(ctx, q.rp, manifestPath(q.image, d))
	if err == nil {
		_, err = h.env.Repos.Delete(ctx, a.ID)
	}
	if err != nil {
		h.fail(w, r, err, codeManifestUnknown)
		return
	}
	// Deleting a manifest removes the tags pointing at it.
	tags, err := h.localTagAssets(ctx, q.rp, q.image)
	if err != nil {
		h.fail(w, r, err, codeManifestUnknown)
		return
	}
	for _, t := range tags {
		if t.Digest == d.String() {
			if _, err := h.env.Repos.Delete(ctx, t.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
				h.fail(w, r, err, codeManifestUnknown)
				return
			}
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// findManifest locates a manifest by digest or tag, consulting the upstream
// (proxy) or members (group).
func (h *Handler) findManifest(ctx context.Context, rp *repo.Repository, image string, d storage.Digest, tag string, depth int) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		a, err := h.proxyManifest(ctx, rp, image, d, tag)
		return rp, a, err
	case repo.KindGroup:
		if depth >= maxDepth {
			return nil, nil, repo.ErrNotFound
		}
		for _, m := range h.env.Members(ctx, rp) {
			owner, a, err := h.findManifest(ctx, m, image, d, tag, depth+1)
			if err == nil {
				return owner, a, nil
			}
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "err", err)
			}
		}
		return nil, nil, repo.ErrNotFound
	default:
		p := tagPath(image, tag)
		if d != "" {
			p = manifestPath(image, d)
		}
		a, err := h.env.Repos.GetAsset(ctx, rp, p)
		return rp, a, err
	}
}

// ---- blobs -----------------------------------------------------------------

func (h *Handler) blobs(w http.ResponseWriter, r *http.Request, q *request, dg string) {
	d, err := storage.ParseDigest(dg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error())
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.authorize(w, r, q, pull) {
			return
		}
		owner, a, err := h.findBlob(r.Context(), q.rp, q.image, d, 0)
		if err != nil {
			h.fail(w, r, err, codeBlobUnknown)
			return
		}
		w.Header().Set("Docker-Content-Digest", a.Digest)
		h.env.Repos.Serve(w, r, owner, a, repo.ServeOptions{ContentType: "application/octet-stream"})
	case http.MethodDelete:
		if !h.authorize(w, r, q, del) || !h.hostedOnly(w, q) {
			return
		}
		a, err := h.env.Repos.GetAsset(r.Context(), q.rp, blobPath(q.image, d))
		if err == nil {
			_, err = h.env.Repos.Delete(r.Context(), a.ID)
		}
		if err != nil {
			h.fail(w, r, err, codeBlobUnknown)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
	}
}

func (h *Handler) findBlob(ctx context.Context, rp *repo.Repository, image string, d storage.Digest, depth int) (*repo.Repository, *store.Asset, error) {
	switch rp.Kind {
	case repo.KindProxy:
		a, err := h.proxyBlob(ctx, rp, image, d)
		return rp, a, err
	case repo.KindGroup:
		if depth >= maxDepth {
			return nil, nil, repo.ErrNotFound
		}
		for _, m := range h.env.Members(ctx, rp) {
			owner, a, err := h.findBlob(ctx, m, image, d, depth+1)
			if err == nil {
				return owner, a, nil
			}
			if !errors.Is(err, repo.ErrNotFound) {
				h.env.Logger.Warn("group member lookup failed", "group", rp.Name, "member", m.Name, "err", err)
			}
		}
		return nil, nil, repo.ErrNotFound
	default:
		a, err := h.env.Repos.GetAsset(ctx, rp, blobPath(image, d))
		if errors.Is(err, repo.ErrNotFound) {
			// Manifests are content too; some clients fetch them as blobs.
			a, err = h.env.Repos.GetAsset(ctx, rp, manifestPath(image, d))
		}
		return rp, a, err
	}
}

// localBlob finds a blob already stored in rp (or its members), without
// contacting upstreams. Used for cross-repository mounts.
func (h *Handler) localBlob(ctx context.Context, rp *repo.Repository, image string, d storage.Digest, depth int) (*repo.Repository, *store.Asset, error) {
	if rp.IsGroup() {
		if depth >= maxDepth {
			return nil, nil, repo.ErrNotFound
		}
		for _, m := range h.env.Members(ctx, rp) {
			if owner, a, err := h.localBlob(ctx, m, image, d, depth+1); err == nil {
				return owner, a, nil
			}
		}
		return nil, nil, repo.ErrNotFound
	}
	if rp.IsProxy() {
		image = upstreamImage(rp, image)
	}
	a, err := h.env.Repos.GetAsset(ctx, rp, blobPath(image, d))
	return rp, a, err
}

// ---- uploads ---------------------------------------------------------------

func chunkKey(id string, n int) string { return fmt.Sprintf("uploads/%s/%d", id, n) }

func (h *Handler) uploads(w http.ResponseWriter, r *http.Request, q *request, id string) {
	if !h.authorize(w, r, q, push) || !h.hostedOnly(w, q) {
		return
	}
	if id == "" {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
			return
		}
		h.startUpload(w, r, q)
		return
	}
	u, ok := h.getUpload(w, r, q, id)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.uploadStatus(w, q, u, http.StatusNoContent)
	case http.MethodPatch:
		h.patchUpload(w, r, q, u)
	case http.MethodPut:
		h.completeUpload(w, r, q, u)
	case http.MethodDelete:
		h.cancelUpload(r.Context(), q, u)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed")
	}
}

func (h *Handler) uploadStatus(w http.ResponseWriter, q *request, u *store.DockerUpload, status int) {
	hd := w.Header()
	hd.Set("Location", q.base()+"/blobs/uploads/"+u.ID)
	hd.Set("Docker-Upload-UUID", u.ID)
	end := u.Size - 1
	if end < 0 {
		end = 0
	}
	hd.Set("Range", fmt.Sprintf("0-%d", end))
	hd.Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (h *Handler) getUpload(w http.ResponseWriter, r *http.Request, q *request, id string) (*store.DockerUpload, bool) {
	if !uploadIDRE.MatchString(id) {
		writeErr(w, http.StatusNotFound, codeBlobUploadUnknown, "blob upload unknown")
		return nil, false
	}
	u, err := h.env.Repos.Store.GetDockerUpload(r.Context(), q.rp.ID, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Image != q.image) {
		writeErr(w, http.StatusNotFound, codeBlobUploadUnknown, "blob upload unknown")
		return nil, false
	}
	if err != nil {
		h.fail(w, r, err, codeBlobUploadUnknown)
		return nil, false
	}
	return u, true
}

func (h *Handler) startUpload(w http.ResponseWriter, r *http.Request, q *request) {
	ctx := r.Context()
	qs := r.URL.Query()
	if m := qs.Get("mount"); m != "" {
		if d, err := storage.ParseDigest(m); err == nil {
			if ok := h.mount(w, r, q, d, qs.Get("from")); ok {
				return
			}
		}
		// Fall back to a regular upload session.
	}
	if dg := qs.Get("digest"); dg != "" {
		d, err := storage.ParseDigest(dg)
		if err != nil {
			writeErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error())
			return
		}
		h.storeBlob(w, r, q, d, http.MaxBytesReader(w, r.Body, MaxBlob))
		return
	}
	u, err := h.env.Repos.Store.CreateDockerUpload(ctx, q.rp.ID, q.image)
	if err != nil {
		h.fail(w, r, err, codeBlobUploadUnknown)
		return
	}
	h.uploadStatus(w, q, u, http.StatusAccepted)
}

// storeBlob ingests body as blob d of the image and answers 201.
func (h *Handler) storeBlob(w http.ResponseWriter, r *http.Request, q *request, d storage.Digest, body io.Reader) bool {
	_, err := h.env.Repos.Put(r.Context(), q.rp, repo.PutOptions{
		Path:           blobPath(q.image, d),
		Body:           body,
		ContentType:    "application/octet-stream",
		ExpectedDigest: d,
		CreatedBy:      format.Actor(r),
	})
	if err != nil {
		h.fail(w, r, err, codeBlobUnknown)
		return false
	}
	blobCreated(w, q, d)
	return true
}

func blobCreated(w http.ResponseWriter, q *request, d storage.Digest) {
	w.Header().Set("Location", q.base()+"/blobs/"+d.String())
	w.Header().Set("Docker-Content-Digest", d.String())
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// mount links blob d from repository `from` into the request image without
// copying, if it is in the same blob store and the caller may read it.
func (h *Handler) mount(w http.ResponseWriter, r *http.Request, q *request, d storage.Digest, from string) bool {
	ctx := r.Context()
	srcRepo, srcImage, ok := splitName(from)
	if q.onHost() {
		// On a repository's own hostname, from names an image of it.
		srcRepo, srcImage, ok = q.rp.Name, from, imageRE.MatchString(from)
	}
	if !ok {
		return false
	}
	src := q.rp
	if srcRepo != q.rp.Name {
		var err error
		src, err = h.env.Repos.Get(ctx, srcRepo)
		if err != nil || src.Format != h.Name() {
			return false
		}
	}
	if !h.env.Can(r, src, pull.authz()) {
		return false
	}
	owner, a, err := h.localBlob(ctx, src, srcImage, d, 0)
	if err != nil || owner.BlobStoreID != q.rp.BlobStoreID {
		return false
	}
	known, _, err := h.env.Repos.Store.BlobKnown(ctx, q.rp.BlobStoreID, d.String())
	if err != nil || !known {
		return false
	}
	if _, err := h.env.Repos.PutStored(ctx, q.rp, d, a.Size, repo.PutOptions{
		Path:        blobPath(q.image, d),
		ContentType: "application/octet-stream",
		CreatedBy:   format.Actor(r),
	}); err != nil {
		h.env.Logger.Warn("docker blob mount failed", "err", err, "digest", d)
		return false
	}
	blobCreated(w, q, d)
	return true
}

// parseContentRange parses "start-end" (optionally prefixed by "bytes ").
func parseContentRange(s string) (start, end int64, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "bytes ")
	s = strings.TrimPrefix(s, "bytes=")
	a, b, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	var err1, err2 error
	start, err1 = strconv.ParseInt(a, 10, 64)
	end, err2 = strconv.ParseInt(strings.SplitN(b, "/", 2)[0], 10, 64)
	return start, end, err1 == nil && err2 == nil && start >= 0 && end >= start-1
}

// appendChunk stores body as the next chunk of the upload.
func (h *Handler) appendChunk(w http.ResponseWriter, r *http.Request, q *request, u *store.DockerUpload, body io.Reader) (*store.DockerUpload, bool) {
	ctx := r.Context()
	var start, end int64
	ranged := false
	if cr := r.Header.Get("Content-Range"); cr != "" {
		var ok bool
		start, end, ok = parseContentRange(cr)
		if !ok {
			writeErr(w, http.StatusBadRequest, codeBlobUploadInvalid, "invalid Content-Range")
			return nil, false
		}
		if start != u.Size {
			h.rangeNotSatisfiable(w, q, u)
			return nil, false
		}
		ranged = true
	}
	bs, err := h.env.Repos.BlobStore(ctx, q.rp)
	if err != nil {
		h.fail(w, r, err, codeBlobUploadUnknown)
		return nil, false
	}
	n, err := bs.PutTemp(ctx, chunkKey(u.ID, u.Chunks), body)
	if err != nil {
		h.fail(w, r, err, codeBlobUploadInvalid)
		return nil, false
	}
	if ranged && end-start+1 != n {
		writeErr(w, http.StatusBadRequest, codeBlobUploadInvalid,
			fmt.Sprintf("Content-Range %d-%d does not match the %d bytes received", start, end, n))
		return nil, false
	}
	u2, err := h.env.Repos.Store.AdvanceDockerUpload(ctx, u.ID, u.Chunks, n)
	if errors.Is(err, store.ErrNotFound) {
		// A concurrent PATCH won; the client is out of sync.
		cur, gerr := h.env.Repos.Store.GetDockerUpload(ctx, q.rp.ID, u.ID)
		if gerr != nil {
			writeErr(w, http.StatusNotFound, codeBlobUploadUnknown, "blob upload unknown")
			return nil, false
		}
		h.rangeNotSatisfiable(w, q, cur)
		return nil, false
	}
	if err != nil {
		h.fail(w, r, err, codeBlobUploadUnknown)
		return nil, false
	}
	return u2, true
}

func (h *Handler) rangeNotSatisfiable(w http.ResponseWriter, q *request, u *store.DockerUpload) {
	hd := w.Header()
	hd.Set("Location", q.base()+"/blobs/uploads/"+u.ID)
	hd.Set("Docker-Upload-UUID", u.ID)
	end := u.Size - 1
	if end < 0 {
		end = 0
	}
	hd.Set("Range", fmt.Sprintf("0-%d", end))
	writeErr(w, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid,
		fmt.Sprintf("chunk must start at offset %d", u.Size))
}

func (h *Handler) patchUpload(w http.ResponseWriter, r *http.Request, q *request, u *store.DockerUpload) {
	u2, ok := h.appendChunk(w, r, q, u, http.MaxBytesReader(w, r.Body, MaxBlob))
	if !ok {
		return
	}
	h.uploadStatus(w, q, u2, http.StatusAccepted)
}

func (h *Handler) completeUpload(w http.ResponseWriter, r *http.Request, q *request, u *store.DockerUpload) {
	ctx := r.Context()
	d, err := storage.ParseDigest(r.URL.Query().Get("digest"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeDigestInvalid, "a valid ?digest= is required: "+err.Error())
		return
	}
	body := bufio.NewReaderSize(http.MaxBytesReader(w, r.Body, MaxBlob), 32<<10)
	hasBody := false
	if r.ContentLength != 0 {
		if _, err := body.Peek(1); err == nil {
			hasBody = true
		}
	}
	var src io.Reader
	switch {
	case hasBody && u.Chunks == 0 && r.Header.Get("Content-Range") == "":
		// Monolithic PUT: stream straight into the blob store.
		src = body
	case hasBody:
		u2, ok := h.appendChunk(w, r, q, u, body)
		if !ok {
			return
		}
		u = u2
		fallthrough
	default:
		bs, err := h.env.Repos.BlobStore(ctx, q.rp)
		if err != nil {
			h.fail(w, r, err, codeBlobUploadUnknown)
			return
		}
		src = &chunkReader{ctx: ctx, bs: bs, id: u.ID, n: u.Chunks}
	}
	if cr, ok := src.(*chunkReader); ok {
		defer cr.Close()
	}
	if !h.storeBlob(w, r, q, d, src) {
		return
	}
	h.cancelUpload(context.WithoutCancel(ctx), q, u)
}

func (h *Handler) cancelUpload(ctx context.Context, q *request, u *store.DockerUpload) {
	if bs, err := h.env.Repos.BlobStore(ctx, q.rp); err == nil {
		if err := bs.DeleteTempPrefix(ctx, "uploads/"+u.ID+"/"); err != nil {
			h.env.Logger.Warn("delete upload chunks", "upload", u.ID, "err", err)
		}
	}
	if err := h.env.Repos.Store.DeleteDockerUpload(ctx, u.ID); err != nil {
		h.env.Logger.Warn("delete upload", "upload", u.ID, "err", err)
	}
}

// chunkReader streams the concatenation of an upload's temp chunks.
type chunkReader struct {
	ctx  context.Context
	bs   storage.BlobStore
	id   string
	n    int
	next int
	cur  io.ReadCloser
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for {
		if c.cur == nil {
			if c.next >= c.n {
				return 0, io.EOF
			}
			rc, err := c.bs.OpenTemp(c.ctx, chunkKey(c.id, c.next))
			if err != nil {
				return 0, fmt.Errorf("open upload chunk %d: %w", c.next, err)
			}
			c.cur = rc
			c.next++
		}
		n, err := c.cur.Read(p)
		if err == io.EOF {
			c.cur.Close()
			c.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *chunkReader) Close() error {
	if c.cur != nil {
		return c.cur.Close()
	}
	return nil
}

// ---- tags and catalog ------------------------------------------------------

func (h *Handler) localTagAssets(ctx context.Context, rp *repo.Repository, image string) ([]*store.Asset, error) {
	prefix := tagPrefix(image)
	var out []*store.Asset
	after := ""
	for {
		as, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, prefix, after, 1000)
		if err != nil {
			return nil, err
		}
		out = append(out, as...)
		if len(as) < 1000 {
			return out, nil
		}
		after = as[len(as)-1].Path
	}
}

func (h *Handler) localTags(ctx context.Context, rp *repo.Repository, image string) ([]string, error) {
	as, err := h.localTagAssets(ctx, rp, image)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(as))
	for _, a := range as {
		t := strings.TrimPrefix(a.Path, tagPrefix(image))
		if t != "" && !strings.Contains(t, "/") {
			out = append(out, t)
		}
	}
	return out, nil
}

// listTags returns the tags of image in rp; found is false when the image
// is unknown.
func (h *Handler) listTags(ctx context.Context, rp *repo.Repository, image string, depth int) (tags []string, found bool, err error) {
	switch rp.Kind {
	case repo.KindProxy:
		up := upstreamImage(rp, image)
		tags, err := h.upstreamTags(ctx, rp, up)
		if err == nil {
			return tags, true, nil
		}
		if !errors.Is(err, repo.ErrNotFound) {
			h.env.Logger.Warn("upstream tags list failed; using cached tags", "repository", rp.Name, "image", up, "err", err)
		}
		tags, lerr := h.localTags(ctx, rp, up)
		return tags, len(tags) > 0, lerr
	case repo.KindGroup:
		if depth >= maxDepth {
			return nil, false, nil
		}
		set := map[string]bool{}
		for _, m := range h.env.Members(ctx, rp) {
			ts, ok, err := h.listTags(ctx, m, image, depth+1)
			if err != nil {
				h.env.Logger.Warn("group member tags failed", "group", rp.Name, "member", m.Name, "err", err)
				continue
			}
			found = found || ok
			for _, t := range ts {
				set[t] = true
			}
		}
		for t := range set {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		return tags, found, nil
	default:
		tags, err := h.localTags(ctx, rp, image)
		if err != nil || len(tags) > 0 {
			return tags, true, err
		}
		any, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, image+"/_", "", 1)
		return tags, len(any) > 0, err
	}
}

// paginate applies the n/last parameters and sets the Link header.
func paginate(w http.ResponseWriter, r *http.Request, items []string, base string) ([]string, bool) {
	qs := r.URL.Query()
	sort.Strings(items)
	if last := qs.Get("last"); last != "" {
		i := sort.SearchStrings(items, last)
		for i < len(items) && items[i] <= last {
			i++
		}
		items = items[i:]
	}
	if ns := qs.Get("n"); ns != "" {
		n, err := strconv.Atoi(ns)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, codeUnsupported, "invalid n")
			return nil, false
		}
		if len(items) > n {
			items = items[:n]
			if n > 0 {
				w.Header().Set("Link", fmt.Sprintf(`<%s?n=%d&last=%s>; rel="next"`, base, n, url.QueryEscape(items[n-1])))
			}
		}
	}
	return items, true
}

func (h *Handler) tagsList(w http.ResponseWriter, r *http.Request, q *request) {
	tags, found, err := h.listTags(r.Context(), q.rp, q.image, 0)
	if err != nil {
		h.fail(w, r, err, codeNameUnknown)
		return
	}
	if !found && len(tags) == 0 {
		writeErr(w, http.StatusNotFound, codeNameUnknown, "repository name not known to registry", map[string]string{"name": q.client})
		return
	}
	tags, ok := paginate(w, r, tags, q.base()+"/tags/list")
	if !ok {
		return
	}
	if tags == nil {
		tags = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": q.client, "tags": tags})
}

// imageNames lists images (with at least one tag) stored in rp.
func (h *Handler) imageNames(ctx context.Context, rp *repo.Repository, depth int) []string {
	if rp.IsGroup() {
		if depth >= maxDepth {
			return nil
		}
		var out []string
		for _, m := range h.env.Members(ctx, rp) {
			out = append(out, h.imageNames(ctx, m, depth+1)...)
		}
		return out
	}
	names, err := h.env.Repos.Store.ListComponentNames(ctx, rp.ID)
	if err != nil {
		h.env.Logger.Warn("catalog", "repository", rp.Name, "err", err)
	}
	return names
}

// catalog lists the images of all docker repositories the caller can read,
// or on a repository's own hostname that repository's images.
func (h *Handler) catalog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set := map[string]bool{}
	if hr := h.hostRepo(r); hr != nil {
		httpx.SetRepository(ctx, hr.Name)
		if h.env.Can(r, hr, pull.authz()) {
			for _, n := range h.imageNames(ctx, hr, 0) {
				set[n] = true
			}
		}
		h.writeCatalog(w, r, set)
		return
	}
	rs, err := h.env.Repos.Store.ListRepositories(ctx)
	if err != nil {
		h.fail(w, r, err, codeNameUnknown)
		return
	}
	for _, x := range rs {
		if x.Format != h.Name() {
			continue
		}
		rp, err := h.env.Repos.Get(ctx, x.Name)
		if err != nil || !h.env.Can(r, rp, pull.authz()) {
			continue
		}
		for _, n := range h.imageNames(ctx, rp, 0) {
			set[rp.Name+"/"+n] = true
		}
	}
	h.writeCatalog(w, r, set)
}

func (h *Handler) writeCatalog(w http.ResponseWriter, r *http.Request, set map[string]bool) {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	names, ok := paginate(w, r, names, "/v2/_catalog")
	if !ok {
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": names})
}
