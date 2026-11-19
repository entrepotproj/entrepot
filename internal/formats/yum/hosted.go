package yum

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/entrepotproj/entrepot/internal/format"
	"github.com/entrepotproj/entrepot/internal/httpx"
	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/storage"
	"github.com/entrepotproj/entrepot/internal/store"
)

// rpmAttrs are stored on each hosted .rpm asset.
type rpmAttrs struct {
	RPM *rpmInfo `json:"rpm"`
}

func depth(rp *repo.Repository) int {
	if rp.Cfg.Hosted == nil || rp.Cfg.Hosted.Yum == nil {
		return 0
	}
	return rp.Cfg.Hosted.Yum.RepodataDepth
}

// rootOf returns the repodata root of a package path, or false when the
// package is above the configured depth.
func rootOf(rp *repo.Repository, p string) (string, bool) {
	d := depth(rp)
	segs := strings.Split(p, "/")
	if len(segs)-1 < d {
		return "", false
	}
	return strings.Join(segs[:d], "/"), true
}

func rootPrefix(root string) string {
	if root == "" {
		return ""
	}
	return root + "/"
}

// ---- Upload ----

func (h *Handler) putUpload(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	f, size, err := h.spool(http.MaxBytesReader(w, r.Body, MaxUpload))
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	defer cleanupSpool(f)
	a, info, err := h.storeRPM(r.Context(), rp, p, f, size, format.Actor(r))
	if err != nil {
		if errors.Is(err, repo.ErrRedeploy) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		h.env.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"path": a.Path, "name": info.Name, "version": info.EVR(), "arch": info.Arch, "sha256": strings.TrimPrefix(a.Digest, "sha256:"),
	})
}

// Upload implements format.Uploader (field "path": the target directory).
func (h *Handler) Upload(ctx context.Context, rp *repo.Repository, u *format.Upload) ([]*store.Asset, error) {
	if !rp.IsHosted() {
		return nil, format.BadRequest("uploads require a hosted repository")
	}
	name := path.Base(strings.ReplaceAll(u.Header.Filename, "\\", "/"))
	dir := strings.Trim(u.Fields["path"], "/")
	if dir == "" {
		dir = u.Fields["directory"]
	}
	p := name
	if dir = strings.Trim(dir, "/"); dir != "" {
		p = dir + "/" + name
	}
	clean, err := format.CleanPath(p)
	if err != nil {
		return nil, format.BadRequest("invalid path %q", p)
	}
	actor := ""
	if u.Uploader != nil {
		actor = u.Uploader.Name
	}
	a, _, err := h.storeRPM(ctx, rp, clean, u.File, u.Header.Size, actor)
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
	f, err := os.CreateTemp(dir, "yum-upload-*")
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

func lockKey(rp *repo.Repository) string { return "yum-metadata:" + rp.ID }

func isReserved(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == "repodata" {
			return true
		}
	}
	return p == "public.key" || strings.HasSuffix(p, "entrepot.repo")
}

func (h *Handler) storeRPM(ctx context.Context, rp *repo.Repository, p string, file io.ReaderAt, size int64, actor string) (*store.Asset, *rpmInfo, error) {
	if !strings.HasSuffix(p, ".rpm") || strings.HasSuffix(p, "/") {
		return nil, nil, format.BadRequest("PUT an .rpm file, e.g. PUT /repository/%s/foo-1.0-1.x86_64.rpm", rp.Name)
	}
	if isReserved(p) {
		return nil, nil, format.BadRequest("%s is reserved for repository metadata", p)
	}
	root, ok := rootOf(rp, p)
	if !ok {
		return nil, nil, format.BadRequest("packages must be at least %d directories deep (hosted.yum.repodataDepth), e.g. el9/x86_64/%s",
			depth(rp), path.Base(p))
	}
	info, err := parseRPM(file, size)
	if err != nil {
		return nil, nil, format.BadRequest("invalid RPM package: %v", err)
	}
	s256 := sha256.New()
	if _, err := io.Copy(s256, io.NewSectionReader(file, 0, size)); err != nil {
		return nil, nil, err
	}
	digest := "sha256:" + hex.EncodeToString(s256.Sum(nil))

	unlock, err := h.env.Repos.Store.AdvisoryLock(ctx, lockKey(rp))
	if err != nil {
		return nil, nil, err
	}
	defer unlock()

	// The same NEVRA elsewhere in the root must be identical.
	if c, err := h.env.Repos.Store.FindComponent(ctx, rp.ID, info.Name, info.EVR()); err == nil {
		others, err := h.env.Repos.Store.ListComponentAssets(ctx, c.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, o := range others {
			var oa rpmAttrs
			if o.Path == p || o.Digest == digest || json.Unmarshal(o.Attrs, &oa) != nil || oa.RPM == nil || oa.RPM.Arch != info.Arch {
				continue
			}
			if r, _ := rootOf(rp, o.Path); r != root {
				continue
			}
			if !rp.AllowRedeploy() {
				return nil, nil, fmt.Errorf("%w: %s already exists at %s with different content", repo.ErrRedeploy, info.NEVRA(), o.Path)
			}
			if _, err := h.env.Repos.Delete(ctx, o.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
				return nil, nil, err
			}
		}
	}

	attrs, _ := json.Marshal(rpmAttrs{RPM: info})
	compAttrs, _ := json.Marshal(map[string]any{
		"arch": info.Arch, "epoch": info.Epoch, "release": info.Release, "summary": info.Summary,
		"license": info.License, "url": info.URL, "vendor": info.Vendor, "sourcerpm": info.SourceRPM,
	})
	a, err := h.env.Repos.Put(ctx, rp, repo.PutOptions{
		Path:           p,
		Body:           io.NewSectionReader(file, 0, size),
		ContentType:    rpmType,
		ExpectedDigest: storage.Digest(digest),
		Attrs:          attrs,
		CreatedBy:      actor,
		Component:      &repo.ComponentRef{Name: info.Name, Version: info.EVR(), Attrs: compAttrs},
		NoOverwrite:    !rp.AllowRedeploy(),
	})
	if err != nil {
		return nil, nil, err
	}
	if err := h.regenerate(ctx, rp, root); err != nil {
		return nil, nil, fmt.Errorf("regenerate repodata: %w", err)
	}
	return a, info, nil
}

// ---- Repodata ----

// Regenerate rebuilds and re-signs the repodata of the given roots (all
// roots when none are given).
func (h *Handler) Regenerate(ctx context.Context, rp *repo.Repository, roots ...string) error {
	if !rp.IsHosted() {
		return nil
	}
	unlock, err := h.env.Repos.Store.AdvisoryLock(ctx, lockKey(rp))
	if err != nil {
		return err
	}
	defer unlock()
	if len(roots) == 0 {
		if roots, err = h.allRoots(ctx, rp); err != nil {
			return err
		}
	}
	for _, root := range roots {
		if err := h.regenerate(ctx, rp, root); err != nil {
			return err
		}
	}
	return nil
}

// Resign regenerates all signed metadata (after a key rotation or import).
func (h *Handler) Resign(ctx context.Context, rp *repo.Repository) error {
	return h.Regenerate(ctx, rp)
}

// AfterDelete implements format.DeleteHook.
func (h *Handler) AfterDelete(ctx context.Context, rp *repo.Repository, deleted []*store.Asset) error {
	if !rp.IsHosted() {
		return nil
	}
	set := map[string]bool{}
	for _, a := range deleted {
		if strings.HasSuffix(a.Path, ".rpm") {
			if root, ok := rootOf(rp, a.Path); ok {
				set[root] = true
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	roots := make([]string, 0, len(set))
	for r := range set {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	return h.Regenerate(ctx, rp, roots...)
}

// walk calls fn for every asset under prefix.
func (h *Handler) walk(ctx context.Context, rp *repo.Repository, prefix string, fn func(*store.Asset) error) error {
	after := ""
	for {
		as, err := h.env.Repos.Store.ListAssets(ctx, rp.ID, prefix, after, 1000)
		if err != nil {
			return err
		}
		for _, a := range as {
			if err := fn(a); err != nil {
				return err
			}
		}
		if len(as) < 1000 {
			return nil
		}
		after = as[len(as)-1].Path
	}
}

func (h *Handler) allRoots(ctx context.Context, rp *repo.Repository) ([]string, error) {
	set := map[string]bool{}
	if depth(rp) == 0 {
		set[""] = true
	}
	err := h.walk(ctx, rp, "", func(a *store.Asset) error {
		switch {
		case strings.HasSuffix(a.Path, ".rpm"):
			if root, ok := rootOf(rp, a.Path); ok {
				set[root] = true
			}
		case strings.HasSuffix(a.Path, "repodata/repomd.xml"):
			root := strings.TrimSuffix(strings.TrimSuffix(a.Path, "repodata/repomd.xml"), "/")
			if strings.Count(rootPrefix(root), "/") == depth(rp) {
				set[root] = true
			}
		}
		return nil
	})
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, err
}

func (h *Handler) regenerate(ctx context.Context, rp *repo.Repository, root string) error {
	prefix := rootPrefix(root)
	var pkgs []*repoPkg
	err := h.walk(ctx, rp, prefix, func(a *store.Asset) error {
		if !strings.HasSuffix(a.Path, ".rpm") {
			return nil
		}
		if r, ok := rootOf(rp, a.Path); !ok || r != root {
			return nil
		}
		var at rpmAttrs
		if err := json.Unmarshal(a.Attrs, &at); err != nil || at.RPM == nil {
			h.env.Logger.Warn("yum: skipping package without header metadata", "repository", rp.Name, "path", a.Path)
			return nil
		}
		pkgs = append(pkgs, &repoPkg{
			Info: at.RPM, Href: strings.TrimPrefix(a.Path, prefix), SHA256: strings.TrimPrefix(a.Digest, "sha256:"),
			Size: a.Size, FileTime: a.CreatedAt.Unix(),
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(pkgs, func(i, j int) bool {
		a, b := pkgs[i].Info, pkgs[j].Info
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Arch != b.Arch {
			return a.Arch < b.Arch
		}
		return pkgs[i].Href < pkgs[j].Href
	})
	files := []mdFile{
		newMDFile("primary", primaryXML(pkgs)),
		newMDFile("filelists", filelistsXML(pkgs)),
		newMDFile("other", otherXML(pkgs)),
	}
	md := prefix + "repodata/"
	// Keep the previous generation so clients that just fetched the old
	// repomd.xml can still download the files it references.
	keep := map[string]bool{md + "repomd.xml": true, md + "repomd.xml.asc": true}
	if old, err := h.env.Repos.GetAsset(ctx, rp, md+"repomd.xml"); err == nil {
		if b, err := h.env.Repos.ReadAll(ctx, rp, old, 16<<20); err == nil {
			for _, href := range repomdLocations(b) {
				keep[prefix+href] = true
			}
		}
	}
	for _, f := range files {
		if _, err := h.env.Repos.PutBytes(ctx, rp, f.Data, repo.PutOptions{
			Path: md + f.Name, ContentType: "application/gzip", CreatedBy: "entrepot",
		}); err != nil {
			return err
		}
		keep[md+f.Name] = true
	}
	repomd := repomdXML(files, time.Now().Unix())
	sig, err := h.env.Signing.DetachSign(ctx, rp.ID, repomd, true)
	if err != nil {
		return fmt.Errorf("sign repomd.xml: %w", err)
	}
	if _, err := h.env.Repos.PutBytes(ctx, rp, repomd, repo.PutOptions{
		Path: md + "repomd.xml", ContentType: "application/xml", CreatedBy: "entrepot",
	}); err != nil {
		return err
	}
	if _, err := h.env.Repos.PutBytes(ctx, rp, sig, repo.PutOptions{
		Path: md + "repomd.xml.asc", ContentType: "application/pgp-signature", CreatedBy: "entrepot",
	}); err != nil {
		return err
	}
	return h.walk(ctx, rp, md, func(a *store.Asset) error {
		if strings.Contains(strings.TrimPrefix(a.Path, md), "/") || keep[a.Path] {
			return nil
		}
		if _, err := h.env.Repos.Delete(ctx, a.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
			return err
		}
		return nil
	})
}

// ---- Serving ----

func (h *Handler) hostedGet(w http.ResponseWriter, r *http.Request, rp *repo.Repository, p string) {
	ctx := r.Context()
	switch {
	case p == "public.key" || p == "RPM-GPG-KEY-entrepot":
		h.servePublicKey(w, r, rp)
		return
	case p == "entrepot.repo" || strings.HasSuffix(p, "/entrepot.repo"):
		h.serveRepoFile(w, r, rp, strings.TrimSuffix(p, "entrepot.repo"))
		return
	}
	a, err := h.env.Repos.GetAsset(ctx, rp, p)
	if errors.Is(err, repo.ErrNotFound) && depth(rp) == 0 && (p == "repodata/repomd.xml" || p == "repodata/repomd.xml.asc") {
		// Empty repository: publish empty (signed) repodata.
		if err = h.Regenerate(ctx, rp, ""); err == nil {
			a, err = h.env.Repos.GetAsset(ctx, rp, p)
		}
	}
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	h.env.Repos.Serve(w, r, rp, a, repo.ServeOptions{ContentType: contentType(p), NoRedirect: strings.Contains(p, "repodata/")})
}

func (h *Handler) servePublicKey(w http.ResponseWriter, r *http.Request, rp *repo.Repository) {
	k, err := h.env.Signing.ActiveKey(r.Context(), rp.ID)
	if err != nil {
		h.env.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("X-Entrepot-Key-Fingerprint", k.Fingerprint)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, k.PublicArmored)
	}
}

func (h *Handler) serveRepoFile(w http.ResponseWriter, r *http.Request, rp *repo.Repository, dir string) {
	base := h.env.URLs.BaseURL(r) + "/repository/" + rp.Name + "/"
	id := "entrepot-" + rp.Name
	if dir != "" {
		id += "-" + strings.ReplaceAll(strings.Trim(dir, "/"), "/", "-")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, "[%s]\n", id)
	fmt.Fprintf(w, "name=%s\n", strings.TrimSpace("Entrepot "+rp.Name+" "+strings.Trim(dir, "/")))
	fmt.Fprintf(w, "baseurl=%s%s\n", base, dir)
	fmt.Fprintf(w, "enabled=1\n")
	if rp.IsHosted() {
		fmt.Fprintf(w, "gpgcheck=0\n")
		fmt.Fprintf(w, "repo_gpgcheck=1\n")
		fmt.Fprintf(w, "gpgkey=%spublic.key\n", base)
	} else {
		fmt.Fprintf(w, "# Packages and repodata are served exactly as published upstream:\n")
		fmt.Fprintf(w, "# enable gpgcheck with the upstream vendor's key.\n")
		fmt.Fprintf(w, "gpgcheck=1\n")
		fmt.Fprintf(w, "#gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-...\n")
	}
}
