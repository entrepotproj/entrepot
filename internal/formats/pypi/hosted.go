package pypi

import (
	"context"
	"crypto/md5" //nolint:gosec // legacy PyPI digests
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
)

// maxDescription bounds the description stored in component attributes.
const maxDescription = 32 << 10

// distUpload is a distribution file to store in a hosted repository.
type distUpload struct {
	File     io.ReaderAt
	Size     int64
	Filename string
	// Meta holds client supplied metadata (twine form fields); embedded
	// metadata fills the gaps.
	Meta   metadata
	SHA256 string
	MD5    string
	Actor  string
}

// legacyUpload implements the upload API used by twine
// (POST multipart/form-data with :action=file_upload).
func (h *Handler) legacyUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid multipart upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck
	switch action := r.FormValue(":action"); action {
	case "file_upload":
	case "submit":
		// Legacy "register": projects are created implicitly on upload.
		_, _ = w.Write([]byte("OK"))
		return
	default:
		http.Error(w, "unsupported :action "+action, http.StatusBadRequest)
		return
	}
	fhs := r.MultipartForm.File["content"]
	if len(fhs) == 0 {
		http.Error(w, "the content field (distribution file) is required", http.StatusBadRequest)
		return
	}
	f, err := fhs[0].Open()
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	defer f.Close()
	form := r.FormValue
	_, err = h.storeDist(r.Context(), rp, distUpload{
		File:     f,
		Size:     fhs[0].Size,
		Filename: fhs[0].Filename,
		Meta: metadata{
			Name:           form("name"),
			Version:        form("version"),
			Summary:        form("summary"),
			Description:    form("description"),
			RequiresPython: form("requires_python"),
			Author:         form("author"),
			AuthorEmail:    form("author_email"),
			License:        form("license"),
			HomePage:       form("home_page"),
			Keywords:       form("keywords"),
		},
		SHA256: form("sha256_digest"),
		MD5:    form("md5_digest"),
		Actor:  format.Actor(r),
	})
	if err != nil {
		if errors.Is(err, repo.ErrRedeploy) {
			http.Error(w, "File already exists with different content: "+path.Base(fhs[0].Filename)+
				" (redeploy is disabled for this repository)", http.StatusConflict)
			return
		}
		h.env.WriteError(w, r, err)
		return
	}
	_, _ = w.Write([]byte("OK"))
}

// Upload implements the generic upload API: a wheel or sdist whose name and
// version come from its embedded metadata or its filename.
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, format.BadRequest("uploads require a hosted repository")
	}
	return h.storeDist(ctx, rp, distUpload{
		File:     u.File,
		Size:     u.Header.Size,
		Filename: u.Header.Filename,
		Meta:     metadata{Name: u.Fields["name"], Version: u.Fields["version"], Summary: u.Fields["summary"]},
		SHA256:   u.Fields["sha256"],
		Actor:    u.Uploader.Name,
	})
}

func (h *Handler) storeDist(ctx context.Context, rp *repo.Repository, u distUpload) ([]*store.Asset, error) {
	filename := path.Base(strings.ReplaceAll(u.Filename, "\\", "/"))
	if !validFilename(filename) {
		return nil, format.BadRequest("invalid filename %q", u.Filename)
	}
	fnName, fnVersion, kind, ok := parseFilename(filename, "")
	if !ok {
		return nil, format.BadRequest("unsupported distribution filename %q (expected a wheel or an sdist such as name-1.0.tar.gz)", filename)
	}

	// Embedded metadata (wheel METADATA / sdist PKG-INFO).
	var rawMeta []byte
	var embedded *metadata
	switch kind {
	case kindWheel:
		b, err := wheelMetadata(u.File, u.Size, fnName, fnVersion)
		if err != nil {
			return nil, format.BadRequest("invalid wheel %s: %v", filename, err)
		}
		rawMeta, embedded = b, parseMetadata(b)
	case kindSdist:
		if b, err := sdistMetadata(u.File, u.Size, filename); err == nil {
			embedded = parseMetadata(b)
		}
	}
	meta := u.Meta
	meta.merge(embedded)
	if meta.Name == "" {
		meta.Name = fnName
	}
	if !ValidName(meta.Name) {
		return nil, format.BadRequest("invalid project name %q", meta.Name)
	}
	project := Normalize(meta.Name)
	if Normalize(fnName) != project {
		n, v, _, ok := parseFilename(filename, project)
		if !ok || Normalize(n) != project {
			return nil, format.BadRequest("filename %q does not match project %q", filename, meta.Name)
		}
		fnVersion = v
	}
	if meta.Version == "" {
		meta.Version = fnVersion
	}
	version := meta.Version
	if !validVersion(version) {
		return nil, format.BadRequest("invalid version %q", version)
	}

	// Verify client digests before storing anything.
	sha := sha256.New()
	md := md5.New() //nolint:gosec
	if _, err := io.Copy(io.MultiWriter(sha, md), io.NewSectionReader(u.File, 0, u.Size)); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(sha.Sum(nil))
	if u.SHA256 != "" && !strings.EqualFold(u.SHA256, sum) {
		return nil, format.BadRequest("sha256_digest mismatch: expected %s, got %s", u.SHA256, sum)
	}
	if got := hex.EncodeToString(md.Sum(nil)); u.MD5 != "" && !strings.EqualFold(u.MD5, got) {
		return nil, format.BadRequest("md5_digest mismatch: expected %s, got %s", u.MD5, got)
	}

	compMeta := meta
	if len(compMeta.Description) > maxDescription {
		compMeta.Description = compMeta.Description[:maxDescription]
	}
	compAttrs, _ := json.Marshal(compMeta)
	comp := &repo.ComponentRef{Name: project, Version: version, Attrs: compAttrs}
	aa := assetAttrs{Filename: filename, PackageType: kind, RequiresPython: meta.RequiresPython}
	if rawMeta != nil {
		ms := sha256.Sum256(rawMeta)
		aa.CoreMetadataSHA256 = hex.EncodeToString(ms[:])
	}
	attrs, _ := json.Marshal(aa)
	p := filePathFor(project, version, filename)
	a, err := h.env.Repos.Put(ctx, rp, repo.PutOptions{
		Path:           p,
		Body:           io.NewSectionReader(u.File, 0, u.Size),
		ContentType:    contentType(filename),
		ExpectedDigest: storage.Digest("sha256:" + sum),
		Attrs:          attrs,
		CreatedBy:      u.Actor,
		Component:      comp,
		NoOverwrite:    !rp.AllowRedeploy(),
	})
	if err != nil {
		return nil, err
	}
	out := []*store.Asset{a}
	if rawMeta != nil {
		m, err := h.env.Repos.PutBytes(ctx, rp, rawMeta, repo.PutOptions{
			Path:        p + metadataSuffix,
			ContentType: contentType(metadataSuffix),
			CreatedBy:   u.Actor,
			Component:   &repo.ComponentRef{Name: project, Version: version},
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
