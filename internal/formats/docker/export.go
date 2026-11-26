package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
)

// ImageManifest is a platform image manifest that a tag or index refers to.
type ImageManifest struct {
	Digest    string
	MediaType string
	Size      int64
	// Platform is os/arch[/variant] for index children ("" for a plain image).
	Platform string
	// Local is true when the manifest is stored in the repository (proxy
	// repositories cache platform manifests only when they are pulled).
	Local bool
}

type indexDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

// exporter resolves manifests and blobs of one image, optionally fetching
// missing content through the proxy.
type exporter struct {
	repos *repo.Service
	h     *Handler // nil: local content only
	rp    *repo.Repository
	image string
}

func (e *exporter) manifest(ctx context.Context, d storage.Digest) (*store.Asset, error) {
	a, err := e.repos.GetAsset(ctx, e.rp, manifestPath(e.image, d))
	if errors.Is(err, repo.ErrNotFound) {
		a, err = e.repos.GetAsset(ctx, e.rp, blobPath(e.image, d))
	}
	if errors.Is(err, repo.ErrNotFound) && e.h != nil && e.rp.IsProxy() {
		a, err = e.h.proxyManifest(ctx, e.rp, e.image, d, "")
	}
	return a, err
}

func (e *exporter) blob(ctx context.Context, d storage.Digest) (*store.Asset, error) {
	a, err := e.repos.GetAsset(ctx, e.rp, blobPath(e.image, d))
	if errors.Is(err, repo.ErrNotFound) {
		a, err = e.repos.GetAsset(ctx, e.rp, manifestPath(e.image, d))
	}
	if errors.Is(err, repo.ErrNotFound) && e.h != nil && e.rp.IsProxy() {
		a, err = e.h.proxyBlob(ctx, e.rp, e.image, d)
	}
	return a, err
}

func (e *exporter) readManifest(ctx context.Context, d storage.Digest) (*store.Asset, []byte, *manifestDoc, string, error) {
	a, err := e.manifest(ctx, d)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("manifest %s: %w", d, err)
	}
	body, err := e.repos.ReadAll(ctx, e.rp, a, MaxManifest)
	if err != nil {
		return nil, nil, nil, "", err
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, nil, "", fmt.Errorf("manifest %s: %w", d, err)
	}
	mt := doc.MediaType
	if mt == "" {
		mt, _ = mediaTypeOf(a.ContentType, &doc)
	}
	return a, body, &doc, mt, nil
}

// layout writes an OCI image layout directory.
type layout struct {
	dir     string
	written map[string]bool
	index   []indexDescriptor
}

func newLayout(dir string) (*layout, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750); err != nil {
		return nil, err
	}
	return &layout{dir: dir, written: map[string]bool{}}, nil
}

func (l *layout) path(d storage.Digest) string {
	return filepath.Join(l.dir, "blobs", "sha256", d.Hex())
}

func (l *layout) writeBytes(d storage.Digest, b []byte) error {
	if l.written[d.String()] {
		return nil
	}
	if err := os.WriteFile(l.path(d), b, 0o640); err != nil {
		return err
	}
	l.written[d.String()] = true
	return nil
}

func (l *layout) writeAsset(ctx context.Context, repos *repo.Service, rp *repo.Repository, d storage.Digest, a *store.Asset) error {
	if l.written[d.String()] {
		return nil
	}
	rc, err := repos.Open(ctx, rp, a)
	if err != nil {
		return fmt.Errorf("blob %s: %w", d, err)
	}
	defer rc.Close()
	f, err := os.OpenFile(l.path(d), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return fmt.Errorf("blob %s: %w", d, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.written[d.String()] = true
	return nil
}

func (l *layout) finish() error {
	if err := os.WriteFile(filepath.Join(l.dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o640); err != nil {
		return err
	}
	idx := map[string]any{"schemaVersion": 2, "mediaType": MediaOCIIndex, "manifests": l.index}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.dir, "index.json"), b, 0o640)
}

// closure writes manifest d and everything it references. Index children
// that are missing are skipped when skipMissingChildren is set.
func (e *exporter) closure(ctx context.Context, l *layout, d storage.Digest, depth int, skipMissingChildren bool) (string, int64, error) {
	if depth > 3 {
		return "", 0, errors.New("index nesting too deep")
	}
	_, body, doc, mt, err := e.readManifest(ctx, d)
	if err != nil {
		return "", 0, err
	}
	if storage.DigestBytes(body) != d {
		return "", 0, fmt.Errorf("manifest %s: stored content does not match its digest", d)
	}
	switch {
	case isIndex(mt):
		for _, c := range doc.Manifests {
			cd, err := storage.ParseDigest(c.Digest)
			if err != nil {
				return "", 0, err
			}
			if _, _, err := e.closure(ctx, l, cd, depth+1, skipMissingChildren); err != nil {
				if skipMissingChildren && errors.Is(err, repo.ErrNotFound) {
					continue
				}
				return "", 0, err
			}
		}
	case isImage(mt) || doc.Config != nil:
		refs := doc.Layers
		if doc.Config != nil {
			refs = append([]descriptor{*doc.Config}, refs...)
		}
		for _, ds := range refs {
			if len(ds.URLs) > 0 || strings.Contains(ds.MediaType, "foreign") || strings.Contains(ds.MediaType, "nondistributable") {
				continue
			}
			bd, err := storage.ParseDigest(ds.Digest)
			if err != nil {
				return "", 0, err
			}
			a, err := e.blob(ctx, bd)
			if err != nil {
				return "", 0, fmt.Errorf("blob %s: %w", bd, err)
			}
			if err := l.writeAsset(ctx, e.repos, e.rp, bd, a); err != nil {
				return "", 0, err
			}
		}
	default:
		return "", 0, fmt.Errorf("manifest %s has unsupported media type %q", d, mt)
	}
	if err := l.writeBytes(d, body); err != nil {
		return "", 0, err
	}
	return mt, int64(len(body)), nil
}

// ExportOCILayout writes the image (or image index, with all its children)
// whose manifest digest is digest to dir as an OCI image layout: oci-layout,
// index.json and blobs/sha256/*. Only content stored in the repository is
// used. image is the component name (the path prefix of the image's assets).
func ExportOCILayout(ctx context.Context, repos *repo.Service, rp *repo.Repository, image, digest, dir string) error {
	e := &exporter{repos: repos, rp: rp, image: image}
	return e.export(ctx, []string{digest}, dir, false)
}

func (e *exporter) export(ctx context.Context, digests []string, dir string, skipMissing bool) error {
	l, err := newLayout(dir)
	if err != nil {
		return err
	}
	for _, dg := range digests {
		d, err := storage.ParseDigest(dg)
		if err != nil {
			return err
		}
		mt, size, err := e.closure(ctx, l, d, 0, skipMissing)
		if err != nil {
			return err
		}
		l.index = append(l.index, indexDescriptor{MediaType: mt, Digest: d.String(), Size: size,
			Annotations: map[string]string{"org.opencontainers.image.ref.name": refName(e.image)}})
	}
	return l.finish()
}

func refName(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// ExportImages writes the given manifests (image manifests or indexes) and
// everything they reference to dir as an OCI image layout. For proxy
// repositories, content not cached yet is fetched from the upstream.
func (h *Handler) ExportImages(ctx context.Context, rp *repo.Repository, image string, digests []string, dir string) error {
	e := &exporter{repos: h.env.Repos, h: h, rp: rp, image: image}
	return e.export(ctx, digests, dir, false)
}

// ImageManifests returns the platform image manifests behind manifest
// digest: the manifest itself for an image, or the children of an index
// (attestation manifests excluded).
func (h *Handler) ImageManifests(ctx context.Context, rp *repo.Repository, image, digest string) ([]ImageManifest, error) {
	e := &exporter{repos: h.env.Repos, h: h, rp: rp, image: image}
	d, err := storage.ParseDigest(digest)
	if err != nil {
		return nil, err
	}
	a, body, _, mt, err := e.readManifest(ctx, d)
	if err != nil {
		return nil, err
	}
	if !isIndex(mt) {
		return []ImageManifest{{Digest: d.String(), MediaType: mt, Size: a.Size, Local: true}}, nil
	}
	var idx struct {
		Manifests []indexDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, err
	}
	var out []ImageManifest
	for _, c := range idx.Manifests {
		if c.MediaType != "" && !isImage(c.MediaType) {
			continue
		}
		if c.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		plat := ""
		if c.Platform != nil {
			if c.Platform.OS == "unknown" {
				continue
			}
			plat = c.Platform.OS + "/" + c.Platform.Architecture
			if c.Platform.Variant != "" {
				plat += "/" + c.Platform.Variant
			}
		}
		cd, err := storage.ParseDigest(c.Digest)
		if err != nil {
			continue
		}
		_, err = h.env.Repos.GetAsset(ctx, rp, manifestPath(image, cd))
		out = append(out, ImageManifest{Digest: cd.String(), MediaType: c.MediaType, Size: c.Size, Platform: plat, Local: err == nil})
	}
	return out, nil
}

// Layer is a layer blob shared by one or more platform images.
type Layer struct {
	Digest    string
	MediaType string
	Size      int64
	// Platforms that use the layer ("" for a plain image).
	Platforms []string
}

// ImageLayers returns the unique layer blobs of the given platform image
// manifests, in manifest order. Config blobs and foreign (non-distributable)
// layers are left out. Manifests a proxy has not cached are fetched from the
// upstream; blobs are not (see OpenBlob).
func (h *Handler) ImageLayers(ctx context.Context, rp *repo.Repository, image string, manifests []ImageManifest) ([]Layer, error) {
	e := &exporter{repos: h.env.Repos, h: h, rp: rp, image: image}
	var out []Layer
	seen := map[string]int{}
	for _, m := range manifests {
		d, err := storage.ParseDigest(m.Digest)
		if err != nil {
			return nil, err
		}
		_, body, doc, mt, err := e.readManifest(ctx, d)
		if err != nil {
			return nil, err
		}
		if storage.DigestBytes(body) != d {
			return nil, fmt.Errorf("manifest %s: stored content does not match its digest", d)
		}
		if !isImage(mt) && doc.Config == nil {
			return nil, fmt.Errorf("manifest %s is not an image manifest (%s)", d, mt)
		}
		for _, l := range doc.Layers {
			if len(l.URLs) > 0 || strings.Contains(l.MediaType, "foreign") || strings.Contains(l.MediaType, "nondistributable") {
				continue
			}
			if _, err := storage.ParseDigest(l.Digest); err != nil {
				return nil, fmt.Errorf("manifest %s: layer %q: %w", d, l.Digest, err)
			}
			if i, ok := seen[l.Digest]; ok {
				if m.Platform != "" && !contains(out[i].Platforms, m.Platform) {
					out[i].Platforms = append(out[i].Platforms, m.Platform)
				}
				continue
			}
			seen[l.Digest] = len(out)
			layer := Layer{Digest: l.Digest, MediaType: l.MediaType, Size: l.Size}
			if m.Platform != "" {
				layer.Platforms = []string{m.Platform}
			}
			out = append(out, layer)
		}
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// OpenBlob opens a blob of the image. For proxy repositories a blob that is
// not cached yet is fetched from the upstream (and cached).
func (h *Handler) OpenBlob(ctx context.Context, rp *repo.Repository, image, digest string) (io.ReadCloser, error) {
	d, err := storage.ParseDigest(digest)
	if err != nil {
		return nil, err
	}
	e := &exporter{repos: h.env.Repos, h: h, rp: rp, image: image}
	a, err := e.blob(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", d, err)
	}
	return h.env.Repos.Open(ctx, rp, a)
}
