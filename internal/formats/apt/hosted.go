package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"  //nolint:gosec // apt index checksums
	"crypto/sha1" //nolint:gosec // apt index checksums
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
)

const (
	defaultDist      = "stable"
	defaultComponent = "main"
)

// defaultArchitectures are published when none are configured and no
// architecture-specific package was uploaded yet.
var defaultArchitectures = []string{"amd64", "arm64"}

// debAttrs are stored on each hosted .deb asset; index generation only
// reads these (never the packages themselves).
type debAttrs struct {
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Component     string   `json:"component"`
	Distributions []string `json:"distributions"`
	// Control is the package's control paragraph.
	Control string `json:"control"`
	MD5     string `json:"md5"`
	SHA1    string `json:"sha1"`
	SHA256  string `json:"sha256"`
}

type uploadReq struct {
	File         io.ReaderAt
	Size         int64
	Filename     string
	Distribution string
	Component    string
	Actor        string
}

// ---- Upload entry points ----

func (h *Handler) putUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	if !strings.HasSuffix(p, ".deb") {
		http.Error(w, "PUT a .deb file, e.g. PUT /repository/"+rp.Name+"/hello_1.0_amd64.deb?distribution=stable&component=main",
			http.StatusBadRequest)
		return
	}
	f, size, err := h.spool(http.MaxBytesReader(w, r.Body, MaxUpload))
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	defer cleanupSpool(f)
	q := r.URL.Query()
	h.respondUpload(w, r, rp, uploadReq{
		File: f, Size: size, Filename: path.Base(p),
		Distribution: q.Get("distribution"), Component: q.Get("component"), Actor: format.Actor(r),
	})
}

func (h *Handler) postUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid multipart upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck
	fhs := r.MultipartForm.File["file"]
	if len(fhs) == 0 {
		http.Error(w, `the multipart field "file" (a .deb) is required`, http.StatusBadRequest)
		return
	}
	f, err := fhs[0].Open()
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	defer f.Close()
	h.respondUpload(w, r, rp, uploadReq{
		File: f, Size: fhs[0].Size, Filename: fhs[0].Filename,
		Distribution: r.FormValue("distribution"), Component: r.FormValue("component"), Actor: format.Actor(r),
	})
}

func (h *Handler) respondUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository, u uploadReq) {
	a, info, err := h.storeDeb(r.Context(), rp, u)
	if err != nil {
		if errors.Is(err, repo.ErrRedeploy) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		h.env.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"path": a.Path, "package": info.Package, "version": info.Version, "architecture": info.Architecture,
		"component": info.Component, "distributions": info.Distributions, "sha256": info.SHA256,
	})
}

// Upload implements format.Uploader (fields: distribution, component).
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, format.BadRequest("uploads require a hosted repository")
	}
	actor := ""
	if u.Uploader != nil {
		actor = u.Uploader.Name
	}
	a, _, err := h.storeDeb(ctx, rp, uploadReq{
		File: u.File, Size: u.Header.Size, Filename: u.Header.Filename,
		Distribution: u.Fields["distribution"], Component: u.Fields["component"], Actor: actor,
	})
	if err != nil {
		return nil, err
	}
	return []*store.Asset{a}, nil
}

func (h *Handler) spool(body io.Reader) (*os.File, int64, error) {
	dir := ""
	if h.env.Config != nil {
		dir = h.env.Config.Storage.TempDir
	}
	f, err := os.CreateTemp(dir, "apt-upload-*")
	if err != nil {
		return nil, 0, err
	}
	n, err := io.Copy(f, body)
	if err != nil {
		cleanupSpool(f)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, 0, format.BadRequest("package exceeds %d bytes", int64(MaxUpload))
		}
		return nil, 0, err
	}
	return f, n, nil
}

func cleanupSpool(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}

// ---- Distribution configuration ----

type distSpec struct {
	Name          string
	Components    []string
	Architectures []string
	Origin        string
	Label         string
}

func configured(rp *repo.Repository) []repo.AptDistribution {
	if rp.Cfg.Hosted == nil || rp.Cfg.Hosted.Apt == nil {
		return nil
	}
	return rp.Cfg.Hosted.Apt.Distributions
}

// resolveTarget validates/defaults the distribution and component of an upload.
func resolveTarget(rp *repo.Repository, dist, comp, arch string) (string, string, error) {
	ds := configured(rp)
	if len(ds) == 0 {
		if dist == "" {
			dist = defaultDist
		}
		if comp == "" {
			comp = defaultComponent
		}
		if !distRe.MatchString(dist) {
			return "", "", format.BadRequest("invalid distribution %q", dist)
		}
		if !componentRe.MatchString(comp) {
			return "", "", format.BadRequest("invalid component %q", comp)
		}
		return dist, comp, nil
	}
	var d *repo.AptDistribution
	if dist == "" {
		if len(ds) > 1 {
			return "", "", format.BadRequest("distribution is required (one of %s)", strings.Join(distNames(ds), ", "))
		}
		d = &ds[0]
	} else {
		for i := range ds {
			if ds[i].Name == dist {
				d = &ds[i]
			}
		}
		if d == nil {
			return "", "", format.BadRequest("unknown distribution %q (configured: %s)", dist, strings.Join(distNames(ds), ", "))
		}
	}
	comps := d.Components
	if len(comps) == 0 {
		comps = []string{defaultComponent}
	}
	if comp == "" {
		comp = comps[0]
	}
	if !slices.Contains(comps, comp) {
		return "", "", format.BadRequest("unknown component %q for distribution %s (configured: %s)", comp, d.Name, strings.Join(comps, ", "))
	}
	if arch != "all" && len(d.Architectures) > 0 && !slices.Contains(d.Architectures, arch) {
		return "", "", format.BadRequest("architecture %q is not published by distribution %s (configured: %s)",
			arch, d.Name, strings.Join(d.Architectures, ", "))
	}
	return d.Name, comp, nil
}

func distNames(ds []repo.AptDistribution) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}

// publishedDists lists the distributions whose indexes exist (configured,
// or "stable" plus every distribution packages were uploaded to).
func publishedDists(rp *repo.Repository, pkgs []*hostedPkg) []distSpec {
	if ds := configured(rp); len(ds) > 0 {
		out := make([]distSpec, 0, len(ds))
		for _, d := range ds {
			s := distSpec{Name: d.Name, Components: d.Components, Architectures: d.Architectures, Origin: d.Origin, Label: d.Label}
			if len(s.Components) == 0 {
				s.Components = []string{defaultComponent}
			}
			out = append(out, s)
		}
		return out
	}
	// "main" is always published so that a default sources.list entry
	// keeps working when it has no packages.
	comps := map[string]map[string]bool{defaultDist: {defaultComponent: true}}
	for _, p := range pkgs {
		for _, d := range p.Attrs.Distributions {
			if comps[d] == nil {
				comps[d] = map[string]bool{defaultComponent: true}
			}
			comps[d][p.Attrs.Component] = true
		}
	}
	out := make([]distSpec, 0, len(comps))
	for d, cs := range comps {
		s := distSpec{Name: d}
		for c := range cs {
			s.Components = append(s.Components, c)
		}
		sort.Strings(s.Components)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- Storing packages ----

func lockKey(rp *repo.Repository) string { return "apt-metadata:" + rp.ID }

func (h *Handler) storeDeb(ctx context.Context, rp *repo.Repository, u uploadReq) (*store.Asset, *debAttrs, error) {
	if u.Filename != "" && !strings.HasSuffix(u.Filename, ".deb") {
		return nil, nil, format.BadRequest("expected a .deb package, got %q", u.Filename)
	}
	info, err := parseDeb(u.File, u.Size)
	if err != nil {
		return nil, nil, format.BadRequest("invalid Debian package: %v", err)
	}
	dist, comp, err := resolveTarget(rp, u.Distribution, u.Component, info.Architecture)
	if err != nil {
		return nil, nil, err
	}
	md := md5.New()  //nolint:gosec
	s1 := sha1.New() //nolint:gosec
	s256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md, s1, s256), io.NewSectionReader(u.File, 0, u.Size)); err != nil {
		return nil, nil, err
	}
	attrs := &debAttrs{
		Package: info.Package, Version: info.Version, Architecture: info.Architecture, Component: comp,
		Distributions: []string{dist},
		Control:       info.Control.Format(indexFields...),
		MD5:           hex.EncodeToString(md.Sum(nil)),
		SHA1:          hex.EncodeToString(s1.Sum(nil)),
		SHA256:        hex.EncodeToString(s256.Sum(nil)),
	}
	p := poolPath(comp, info.Package, info.Version, info.Architecture)

	unlock, err := h.env.Repos.Store.AdvisoryLock(ctx, lockKey(rp))
	if err != nil {
		return nil, nil, err
	}
	defer unlock()

	digest := "sha256:" + attrs.SHA256
	if prev, err := h.env.Repos.GetAsset(ctx, rp, p); err == nil {
		if prev.Digest != digest && !rp.AllowRedeploy() {
			return nil, nil, fmt.Errorf("%w: %s %s (%s) already exists with different content", repo.ErrRedeploy,
				info.Package, info.Version, info.Architecture)
		}
		var old debAttrs
		if json.Unmarshal(prev.Attrs, &old) == nil {
			attrs.Distributions = union(old.Distributions, attrs.Distributions)
		}
	} else if !errors.Is(err, repo.ErrNotFound) {
		return nil, nil, err
	}
	// The same package/version/arch in another component must be identical.
	if c, err := h.env.Repos.Store.FindComponent(ctx, rp.ID, info.Package, info.Version); err == nil {
		others, err := h.env.Repos.Store.ListComponentAssets(ctx, c.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, o := range others {
			var oa debAttrs
			if o.Path == p || json.Unmarshal(o.Attrs, &oa) != nil || oa.Architecture != info.Architecture || o.Digest == digest {
				continue
			}
			if !rp.AllowRedeploy() {
				return nil, nil, fmt.Errorf("%w: %s %s (%s) already exists in component %s with different content",
					repo.ErrRedeploy, info.Package, info.Version, info.Architecture, oa.Component)
			}
			if _, err := h.env.Repos.Delete(ctx, o.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
				return nil, nil, err
			}
		}
	}

	rawAttrs, _ := json.Marshal(attrs)
	compAttrs, _ := json.Marshal(map[string]any{
		"architecture": info.Architecture, "component": comp, "distributions": attrs.Distributions,
		"maintainer": info.Control.Get("Maintainer"), "section": info.Control.Get("Section"),
		"depends": info.Control.Get("Depends"), "description": summary(info.Control.Get("Description")),
		"homepage": info.Control.Get("Homepage"),
	})
	a, err := h.env.Repos.Put(ctx, rp, repo.PutOptions{
		Path:           p,
		Body:           io.NewSectionReader(u.File, 0, u.Size),
		ContentType:    debType,
		ExpectedDigest: storage.Digest(digest),
		Attrs:          rawAttrs,
		CreatedBy:      u.Actor,
		Component:      &repo.ComponentRef{Name: info.Package, Version: info.Version, Attrs: compAttrs},
		NoOverwrite:    !rp.AllowRedeploy(),
	})
	if err != nil {
		return nil, nil, err
	}
	if err := h.regenerate(ctx, rp); err != nil {
		return nil, nil, fmt.Errorf("regenerate indexes: %w", err)
	}
	return a, attrs, nil
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func summary(desc string) string {
	s, _, _ := strings.Cut(desc, "\n")
	return strings.TrimSpace(s)
}

// indexFields are added by the repository and never taken from control.
var indexFields = []string{"Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Status"}

// ---- Index generation ----

type hostedPkg struct {
	Asset *store.Asset
	Attrs debAttrs
}

// Regenerate rebuilds and re-signs all indexes of a hosted repository.
func (h *Handler) Regenerate(ctx context.Context, rp *repo.Repository) error {
	if !rp.IsHosted() {
		return nil
	}
	unlock, err := h.env.Repos.Store.AdvisoryLock(ctx, lockKey(rp))
	if err != nil {
		return err
	}
	defer unlock()
	return h.regenerate(ctx, rp)
}

// Resign regenerates the signed metadata (after a key rotation or import).
func (h *Handler) Resign(ctx context.Context, rp *repo.Repository) error {
	return h.Regenerate(ctx, rp)
}

// AfterDelete implements format.DeleteHook.
func (h *Handler) AfterDelete(ctx context.Context, rp *repo.Repository, deleted []*store.Asset) error {
	if !rp.IsHosted() {
		return nil
	}
	for _, a := range deleted {
		if strings.HasPrefix(a.Path, "pool/") {
			return h.Regenerate(ctx, rp)
		}
	}
	return nil
}

func (h *Handler) listPackages(ctx context.Context, rp *repo.Repository) ([]*hostedPkg, error) {
	var out []*hostedPkg
	after := ""
	for {
		as, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, "pool/", after, 1000)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			if !strings.HasSuffix(a.Path, ".deb") {
				continue
			}
			var at debAttrs
			if err := json.Unmarshal(a.Attrs, &at); err != nil || at.Package == "" || at.Control == "" {
				h.env.Logger.Warn("apt: skipping package without index metadata", "repository", rp.Name, "path", a.Path)
				continue
			}
			out = append(out, &hostedPkg{Asset: a, Attrs: at})
		}
		if len(as) < 1000 {
			return out, nil
		}
		after = as[len(as)-1].Path
	}
}

type genFile struct {
	path string
	data []byte
}

func (h *Handler) regenerate(ctx context.Context, rp *repo.Repository) error {
	pkgs, err := h.listPackages(ctx, rp)
	if err != nil {
		return err
	}
	sort.Slice(pkgs, func(i, j int) bool {
		a, b := pkgs[i].Attrs, pkgs[j].Attrs
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Architecture < b.Architecture
	})
	now := time.Now().UTC()
	keep := map[string]bool{}
	for _, d := range publishedDists(rp, pkgs) {
		files, err := h.buildDist(ctx, rp, d, pkgs, now)
		if err != nil {
			return err
		}
		for _, f := range files {
			if _, err := h.env.Repos.PutBytes(ctx, rp, f.data, repo.PutOptions{
				Path: f.path, ContentType: contentType(f.path), CreatedBy: "entrepot",
			}); err != nil {
				return err
			}
			keep[f.path] = true
		}
	}
	// Remove indexes of distributions/components/architectures that are no
	// longer published.
	after := ""
	for {
		as, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, "dists/", after, 1000)
		if err != nil {
			return err
		}
		for _, a := range as {
			if !keep[a.Path] {
				if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
					return err
				}
			}
		}
		if len(as) < 1000 {
			return nil
		}
		after = as[len(as)-1].Path
	}
}

func (h *Handler) buildDist(ctx context.Context, rp *repo.Repository, d distSpec, pkgs []*hostedPkg, now time.Time) ([]genFile, error) {
	var inDist []*hostedPkg
	for _, p := range pkgs {
		if slices.Contains(p.Attrs.Distributions, d.Name) {
			inDist = append(inDist, p)
		}
	}
	// Architectures: configured, else derived from the uploads.
	var archs []string
	withAll := false
	for _, a := range d.Architectures {
		if a == "all" {
			withAll = true
		} else if !slices.Contains(archs, a) {
			archs = append(archs, a)
		}
	}
	if len(d.Architectures) == 0 {
		for _, p := range inDist {
			if a := p.Attrs.Architecture; a != "all" && !slices.Contains(archs, a) {
				archs = append(archs, a)
			}
		}
		if len(archs) == 0 {
			archs = slices.Clone(defaultArchitectures)
		}
	}
	sort.Strings(archs)
	indexArchs := slices.Clone(archs)
	if withAll {
		indexArchs = append(indexArchs, "all")
	}

	var files []genFile
	for _, comp := range d.Components {
		for _, arch := range indexArchs {
			var b bytes.Buffer
			for _, p := range inDist {
				if p.Attrs.Component != comp || (p.Attrs.Architecture != arch && p.Attrs.Architecture != "all") {
					continue
				}
				writeEntry(&b, p)
			}
			rel := comp + "/binary-" + arch + "/"
			files = append(files,
				genFile{path: rel + "Packages", data: b.Bytes()},
				genFile{path: rel + "Packages.gz", data: gzipBytes(b.Bytes())},
				genFile{path: rel + "Release", data: []byte(fmt.Sprintf(
					"Archive: %s\nComponent: %s\nOrigin: %s\nLabel: %s\nArchitecture: %s\n",
					d.Name, comp, origin(rp, d), label(rp, d), arch))},
			)
		}
	}
	release := buildRelease(rp, d, archs, withAll, files, now)
	// Like Debian's InRelease: the signature follows the last line directly.
	inRelease, err := h.env.Signing.ClearSign(ctx, rp.ID, bytes.TrimRight(release, "\n"))
	if err != nil {
		return nil, fmt.Errorf("sign InRelease: %w", err)
	}
	sig, err := h.env.Signing.DetachSign(ctx, rp.ID, release, false)
	if err != nil {
		return nil, fmt.Errorf("sign Release.gpg: %w", err)
	}
	prefix := "dists/" + d.Name + "/"
	out := make([]genFile, 0, len(files)+3)
	for _, f := range files {
		out = append(out, genFile{path: prefix + f.path, data: f.data})
	}
	return append(out,
		genFile{path: prefix + "Release", data: release},
		genFile{path: prefix + "InRelease", data: inRelease},
		genFile{path: prefix + "Release.gpg", data: sig},
	), nil
}

func origin(rp *repo.Repository, d distSpec) string {
	if d.Origin != "" {
		return d.Origin
	}
	return "Entrepot"
}

func label(rp *repo.Repository, d distSpec) string {
	if d.Label != "" {
		return d.Label
	}
	return rp.Name
}

func writeEntry(b *bytes.Buffer, p *hostedPkg) {
	ctl := strings.TrimRight(p.Attrs.Control, "\n")
	b.WriteString(ctl)
	b.WriteString("\n")
	fmt.Fprintf(b, "Filename: %s\nSize: %d\nMD5sum: %s\nSHA1: %s\nSHA256: %s\n\n",
		p.Asset.Path, p.Asset.Size, p.Attrs.MD5, p.Attrs.SHA1, p.Attrs.SHA256)
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// releaseDate formats t as apt expects (RFC 2822, UTC).
func releaseDate(t time.Time) string { return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC") }

func buildRelease(rp *repo.Repository, d distSpec, archs []string, withAll bool, files []genFile, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Origin: %s\n", origin(rp, d))
	fmt.Fprintf(&b, "Label: %s\n", label(rp, d))
	fmt.Fprintf(&b, "Suite: %s\n", d.Name)
	fmt.Fprintf(&b, "Codename: %s\n", d.Name)
	fmt.Fprintf(&b, "Date: %s\n", releaseDate(now))
	pubArchs := slices.Clone(archs)
	if withAll {
		pubArchs = append(pubArchs, "all")
	}
	fmt.Fprintf(&b, "Architectures: %s\n", strings.Join(pubArchs, " "))
	fmt.Fprintf(&b, "Components: %s\n", strings.Join(d.Components, " "))
	fmt.Fprintf(&b, "Description: %s %s\n", rp.Name, d.Name)
	if withAll {
		// arch:all packages are also listed in each binary-{arch} index.
		b.WriteString("No-Support-for-Architecture-all: Packages\n")
	}
	b.WriteString("Acquire-By-Hash: no\n")
	sorted := slices.Clone(files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })
	type sum struct {
		name string
		fn   func([]byte) string
	}
	for _, s := range []sum{
		{"MD5Sum", func(x []byte) string { v := md5.Sum(x); return hex.EncodeToString(v[:]) }}, //nolint:gosec
		{"SHA1", func(x []byte) string { v := sha1.Sum(x); return hex.EncodeToString(v[:]) }},  //nolint:gosec
		{"SHA256", func(x []byte) string { v := sha256.Sum256(x); return hex.EncodeToString(v[:]) }},
	} {
		b.WriteString(s.name + ":\n")
		for _, f := range sorted {
			fmt.Fprintf(&b, " %s %16d %s\n", s.fn(f.data), len(f.data), f.path)
		}
	}
	return []byte(b.String())
}

// ---- Serving ----

func (h *Handler) hostedGet(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	switch p {
	case "public.key", "public.gpg", "public.asc":
		h.servePublicKey(w, r, rp, p != "public.gpg")
		return
	case "":
		h.usage(w, r, rp)
		return
	}
	a, err := h.env.Repos.GetAsset(ctx, rp, p)
	if errors.Is(err, repo.ErrNotFound) && h.isReleaseFile(rp, p) {
		// First request for a distribution: publish (empty) indexes.
		if err = h.Regenerate(ctx, rp); err == nil {
			a, err = h.env.Repos.GetAsset(ctx, rp, p)
		}
	}
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, rp, a, repo.ServeOptions{ContentType: contentType(p), NoRedirect: strings.HasPrefix(p, "dists/")})
}

func (h *Handler) isReleaseFile(rp *repo.Repository, p string) bool {
	rest, ok := strings.CutPrefix(p, "dists/")
	if !ok {
		return false
	}
	dist, file, ok := strings.Cut(rest, "/")
	if !ok || (file != "InRelease" && file != "Release" && file != "Release.gpg") {
		return false
	}
	if ds := configured(rp); len(ds) > 0 {
		return slices.Contains(distNames(ds), dist)
	}
	return dist == defaultDist
}

func (h *Handler) servePublicKey(w http.ResponseWriter, r *http.Request, rp *repo.Repository, armored bool) {
	k, err := h.env.Signing.ActiveKey(r.Context(), rp.ID)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	body := []byte(k.PublicArmored)
	ct := "application/pgp-keys"
	if !armored {
		if body, err = k.PublicBinary(); err != nil {
			h.env.WriteError(w, r, err)
			return
		}
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Entrepot-Key-Fingerprint", k.Fingerprint)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (h *Handler) usage(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	base := h.env.URLs.BaseURL(r) + "/repository/" + rp.Name
	dist, comp := defaultDist, defaultComponent
	if ds := configured(rp); len(ds) > 0 {
		dist = ds[0].Name
		if len(ds[0].Components) > 0 {
			comp = strings.Join(ds[0].Components, " ")
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Entrepot apt repository %s\n\n", rp.Name)
	fmt.Fprintf(w, "  curl -fsSL %s/public.gpg | sudo tee /usr/share/keyrings/entrepot-%s.gpg >/dev/null\n", base, rp.Name)
	fmt.Fprintf(w, "  echo 'deb [signed-by=/usr/share/keyrings/entrepot-%s.gpg] %s %s %s' | sudo tee /etc/apt/sources.list.d/entrepot-%s.list\n",
		rp.Name, base, dist, comp, rp.Name)
	fmt.Fprintf(w, "\nUpload: curl -u USER:TOKEN -F file=@pkg.deb -F distribution=%s -F component=%s %s/\n", dist, defaultComponent, base)
}
