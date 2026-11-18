package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/geoffo-dev/package-repository/internal/api/apigen"
	"github.com/geoffo-dev/package-repository/internal/authz"
	"github.com/geoffo-dev/package-repository/internal/format"
	"github.com/geoffo-dev/package-repository/internal/httpx"
	"github.com/geoffo-dev/package-repository/internal/repo"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ---- Blob stores ----

func (s *Server) blobStoreToAPI(ctx context.Context, b *store.BlobStore) apigen.BlobStore {
	out := apigen.BlobStore{
		Name: b.Name, Type: apigen.BlobStoreType(b.Type), CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
	}
	switch b.Type {
	case "file":
		var fc apigen.FileBlobStoreConfig
		_ = json.Unmarshal(b.Config, &fc)
		out.File = &fc
	case "s3":
		var sc apigen.S3BlobStoreConfig
		_ = json.Unmarshal(b.Config, &sc)
		sc.SecretAccessKey = nil // never returned
		out.S3 = &sc
	}
	if u, err := s.Store.BlobStoreUsage(ctx, b.ID); err == nil {
		out.Usage.BlobCount, out.Usage.TotalBytes, out.Usage.Repositories = u.BlobCount, u.TotalBytes, u.Repositories
	}
	return out
}

// blobStoreConfig converts API input to the stored JSON config. For updates
// of S3 stores, an omitted secret keeps the previous one.
func blobStoreConfig(in apigen.BlobStoreInput, prev json.RawMessage) (json.RawMessage, error) {
	switch in.Type {
	case "file":
		if in.File == nil || in.File.Path == "" {
			return nil, errBad("file.path is required for file blob stores")
		}
		return json.Marshal(storage.FileConfig{Path: in.File.Path})
	case "s3":
		if in.S3 == nil || in.S3.Bucket == "" {
			return nil, errBad("s3.bucket is required for s3 blob stores")
		}
		sc := storage.S3Config{
			Bucket:            in.S3.Bucket,
			Region:            deref(in.S3.Region),
			Prefix:            deref(in.S3.Prefix),
			Endpoint:          deref(in.S3.Endpoint),
			ForcePathStyle:    deref(in.S3.ForcePathStyle),
			AccessKeyID:       deref(in.S3.AccessKeyId),
			SecretAccessKey:   deref(in.S3.SecretAccessKey),
			RedirectDownloads: deref(in.S3.RedirectDownloads),
		}
		if sc.SecretAccessKey == "" && prev != nil {
			var old storage.S3Config
			if json.Unmarshal(prev, &old) == nil && old.AccessKeyID == sc.AccessKeyID {
				sc.SecretAccessKey = old.SecretAccessKey
			}
		}
		if sc.AccessKeyID != "" && sc.SecretAccessKey == "" {
			return nil, errBad("s3.secretAccessKey is required with s3.accessKeyId")
		}
		return json.Marshal(sc)
	default:
		return nil, errBad("type must be file or s3")
	}
}

func (s *Server) ListBlobStores(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	bs, err := s.Store.ListBlobStores(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.BlobStore, 0, len(bs))
	for _, b := range bs {
		out = append(out, s.blobStoreToAPI(r.Context(), b))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateBlobStore(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.BlobStoreInput
	if !decode(w, r, &in) {
		return
	}
	if !nameRE.MatchString(in.Name) {
		s.writeErr(w, errBad("invalid name: use lowercase letters, digits, '.', '_' and '-'"))
		return
	}
	cfg, err := blobStoreConfig(in, nil)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.checkBlobStore(r.Context(), string(in.Type), cfg); err != nil {
		s.writeErr(w, err)
		return
	}
	b, err := s.Store.CreateBlobStore(r.Context(), &store.BlobStore{Name: in.Name, Type: string(in.Type), Config: cfg})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "blobstore.create", b.Name, map[string]string{"type": b.Type})
	httpx.WriteJSON(w, http.StatusCreated, s.blobStoreToAPI(r.Context(), b))
}

// checkBlobStore builds the store and verifies it is reachable and writable.
func (s *Server) checkBlobStore(ctx context.Context, typ string, cfg json.RawMessage) error {
	bs, err := s.Blobs.Build(ctx, typ, cfg)
	if err != nil {
		return errBad(err.Error())
	}
	if err := bs.Check(ctx); err != nil {
		return errBad("blob store check failed: " + err.Error())
	}
	return nil
}

func (s *Server) GetBlobStore(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.Store.GetBlobStore(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.blobStoreToAPI(r.Context(), b))
}

func (s *Server) UpdateBlobStore(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.BlobStoreInput
	if !decode(w, r, &in) {
		return
	}
	prev, err := s.Store.GetBlobStore(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if in.Name != name || string(in.Type) != prev.Type {
		s.writeErr(w, errBad("name and type of a blob store cannot be changed"))
		return
	}
	cfg, err := blobStoreConfig(in, prev.Config)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.checkBlobStore(r.Context(), prev.Type, cfg); err != nil {
		s.writeErr(w, err)
		return
	}
	b, err := s.Store.UpdateBlobStore(r.Context(), name, cfg)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Blobs.Forget(b.ID)
	s.audit(r, "blobstore.update", name, nil)
	httpx.WriteJSON(w, http.StatusOK, s.blobStoreToAPI(r.Context(), b))
}

func (s *Server) DeleteBlobStore(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.Store.GetBlobStore(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.DeleteBlobStore(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Blobs.Forget(b.ID)
	s.audit(r, "blobstore.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Repositories ----

func (s *Server) repoToAPI(r *http.Request, rp *repo.Repository, withStats bool) apigen.Repository {
	ctx := r.Context()
	out := apigen.Repository{
		Name:          rp.Name,
		Format:        rp.Format,
		Kind:          apigen.RepositoryKind(rp.Kind),
		BlobStore:     rp.BlobStoreName,
		Description:   rp.Description,
		Online:        rp.Online,
		AnonymousRead: rp.AnonymousRead,
		Url:           s.Formats.ClientURL(s.URLs.BaseURL(r), rp),
		Permissions:   s.Authz.Permissions(ctx, principal(r), format.Target(rp)),
		CreatedAt:     rp.CreatedAt,
		UpdatedAt:     rp.UpdatedAt,
	}
	if pc := rp.Cfg.Proxy; pc != nil {
		out.Proxy = &apigen.ProxySettings{RemoteUrl: pc.RemoteURL}
		if pc.Username != "" {
			out.Proxy.Username = ptr(pc.Username)
		}
		if pc.MetadataTTLSeconds != 0 {
			out.Proxy.MetadataTtlSeconds = ptr(pc.MetadataTTLSeconds)
		}
		if pc.ContentTTLSeconds != 0 {
			out.Proxy.ContentTtlSeconds = ptr(pc.ContentTTLSeconds)
		}
		if pc.NegativeCacheTTLSeconds != 0 {
			out.Proxy.NegativeCacheTtlSeconds = ptr(pc.NegativeCacheTTLSeconds)
		}
	}
	if hc := rp.Cfg.Hosted; hc != nil && rp.IsHosted() {
		out.Hosted = &apigen.HostedSettings{AllowRedeploy: ptr(hc.AllowRedeploy)}
	}
	if gc := rp.Cfg.Group; gc != nil {
		out.Group = &apigen.GroupSettings{Members: gc.Members}
	}
	if withStats {
		if st, err := s.Store.RepositoryStats(ctx, rp.ID); err == nil {
			out.Stats = &apigen.RepositoryStats{Assets: st.Assets, Components: st.Components, TotalBytes: st.TotalBytes}
		}
	}
	return out
}

// repoConfig builds and validates the stored config from API input.
func (s *Server) repoConfig(ctx context.Context, in apigen.RepositoryInput, prev *repo.Repository) (json.RawMessage, error) {
	h, ok := s.Formats.Get(string(in.Format))
	if !ok {
		return nil, errBad(fmt.Sprintf("unsupported format %q", in.Format))
	}
	if !format.Supports(h, string(in.Kind)) {
		return nil, errBad(fmt.Sprintf("format %s does not support %s repositories", in.Format, in.Kind))
	}
	var cfg repo.Config
	switch in.Kind {
	case repo.KindProxy:
		if in.Proxy == nil {
			return nil, errBad("proxy settings are required for proxy repositories")
		}
		p := in.Proxy
		if !strings.HasPrefix(p.RemoteUrl, "http://") && !strings.HasPrefix(p.RemoteUrl, "https://") {
			return nil, errBad("proxy.remoteUrl must be an http(s) URL")
		}
		cfg.Proxy = &repo.ProxyConfig{
			RemoteURL:               strings.TrimRight(p.RemoteUrl, "/"),
			Username:                deref(p.Username),
			Password:                deref(p.Password),
			MetadataTTLSeconds:      deref(p.MetadataTtlSeconds),
			ContentTTLSeconds:       deref(p.ContentTtlSeconds),
			NegativeCacheTTLSeconds: deref(p.NegativeCacheTtlSeconds),
		}
		// Keep the stored password when the client omits it.
		if cfg.Proxy.Password == "" && prev != nil && prev.Cfg.Proxy != nil && prev.Cfg.Proxy.Username == cfg.Proxy.Username {
			cfg.Proxy.Password = prev.Cfg.Proxy.Password
		}
	case repo.KindHosted:
		cfg.Hosted = &repo.HostedConfig{}
		if in.Hosted != nil && in.Hosted.AllowRedeploy != nil {
			cfg.Hosted.AllowRedeploy = *in.Hosted.AllowRedeploy
		} else if in.Format == "docker" {
			// For Docker, "redeploy" means moving tags (latest, main, ...),
			// which registries normally allow.
			cfg.Hosted.AllowRedeploy = true
		}
	case repo.KindGroup:
		if in.Group == nil || len(in.Group.Members) == 0 {
			return nil, errBad("group.members is required for group repositories")
		}
		for _, m := range in.Group.Members {
			if m == in.Name {
				return nil, errBad("a group cannot contain itself")
			}
			mr, err := s.Repos.Get(ctx, m)
			if err != nil {
				return nil, errBad("group member " + m + " does not exist")
			}
			if mr.Format != string(in.Format) {
				return nil, errBad("group member " + m + " has format " + mr.Format)
			}
		}
		cfg.Group = &repo.GroupConfig{Members: in.Group.Members}
	default:
		return nil, errBad("kind must be hosted, proxy or group")
	}
	if v, ok := h.(format.Validator); ok {
		if err := v.ValidateRepository(string(in.Kind), cfg); err != nil {
			return nil, errBad(err.Error())
		}
	}
	return json.Marshal(cfg)
}

func (s *Server) ListRepositories(w http.ResponseWriter, r *http.Request, params apigen.ListRepositoriesParams) {
	rs, err := s.Store.ListRepositories(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := []apigen.Repository{}
	for _, x := range rs {
		if params.Format != nil && *params.Format != "" && x.Format != *params.Format {
			continue
		}
		rp, err := s.Repos.Get(r.Context(), x.Name)
		if err != nil {
			continue
		}
		if !s.Authz.Can(r.Context(), principal(r), authz.Read, format.Target(rp)) {
			continue
		}
		out = append(out, s.repoToAPI(r, rp, false))
	}
	if len(out) == 0 && principal(r).IsAnonymous() && len(rs) > 0 {
		// Hint to the UI that logging in may reveal more.
		w.Header().Set("X-Entrepot-Anonymous", "true")
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) CreateRepository(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in apigen.RepositoryInput
	if !decode(w, r, &in) {
		return
	}
	if !nameRE.MatchString(in.Name) {
		s.writeErr(w, errBad("invalid name: use lowercase letters, digits, '.', '_' and '-'"))
		return
	}
	cfg, err := s.repoConfig(r.Context(), in, nil)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	created, err := s.Store.CreateRepository(r.Context(), &store.Repository{
		Name:          in.Name,
		Format:        string(in.Format),
		Kind:          string(in.Kind),
		BlobStoreName: in.BlobStore,
		Description:   deref(in.Description),
		Online:        in.Online == nil || *in.Online,
		AnonymousRead: deref(in.AnonymousRead),
		Config:        cfg,
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	rp, err := s.Repos.Get(r.Context(), created.Name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "repository.create", rp.Name, map[string]string{"format": rp.Format, "kind": rp.Kind})
	httpx.WriteJSON(w, http.StatusCreated, s.repoToAPI(r, rp, true))
}

func (s *Server) GetRepository(w http.ResponseWriter, r *http.Request, name string) {
	rp, ok := s.requireRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.repoToAPI(r, rp, true))
}

func (s *Server) UpdateRepository(w http.ResponseWriter, r *http.Request, name string) {
	rp, ok := s.requireRepo(w, r, name, authz.Admin)
	if !ok {
		return
	}
	var in apigen.RepositoryInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name != name || string(in.Format) != rp.Format || string(in.Kind) != rp.Kind || in.BlobStore != rp.BlobStoreName {
		s.writeErr(w, errBad("name, format, kind and blobStore cannot be changed"))
		return
	}
	cfg, err := s.repoConfig(r.Context(), in, rp)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	_, err = s.Store.UpdateRepository(r.Context(), &store.Repository{
		Name:          name,
		Description:   deref(in.Description),
		Online:        in.Online == nil || *in.Online,
		AnonymousRead: deref(in.AnonymousRead),
		Config:        cfg,
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.Repos.Invalidate(name)
	rp, err = s.Repos.Get(r.Context(), name)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "repository.update", name, nil)
	httpx.WriteJSON(w, http.StatusOK, s.repoToAPI(r, rp, true))
}

func (s *Server) DeleteRepository(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := s.requireRepo(w, r, name, authz.Admin); !ok {
		return
	}
	if err := s.Store.DeleteRepository(r.Context(), name); err != nil {
		s.writeErr(w, err)
		return
	}
	s.Repos.Invalidate(name)
	s.audit(r, "repository.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Assets & components ----

func (s *Server) assetToAPI(r *http.Request, a *store.Asset) apigen.Asset {
	out := apigen.Asset{
		Id: a.ID, Repository: a.Repository, ComponentId: a.ComponentID, Path: a.Path, Digest: a.Digest,
		Size: a.Size, ContentType: a.ContentType, CreatedBy: a.CreatedBy, CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt, CachedAt: a.CachedAt, LastDownloadedAt: a.LastDownloadedAt,
		DownloadUrl: ptr(s.URLs.BaseURL(r) + "/api/v1/assets/" + a.ID + "/content"),
	}
	_ = json.Unmarshal(a.Attrs, &out.Attrs)
	if out.Attrs == nil {
		out.Attrs = map[string]any{}
	}
	return out
}

func (s *Server) componentToAPI(c *store.Component) apigen.Component {
	out := apigen.Component{
		Id: c.ID, Repository: c.Repository, Format: c.Format, Name: c.Name, Version: c.Version,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	_ = json.Unmarshal(c.Attrs, &out.Attrs)
	if out.Attrs == nil {
		out.Attrs = map[string]any{}
	}
	return out
}

func (s *Server) ListAssets(w http.ResponseWriter, r *http.Request, name string, params apigen.ListAssetsParams) {
	rp, ok := s.requireRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	limit := deref(params.Limit)
	if limit <= 0 {
		limit = 100
	}
	as, err := s.Store.ListAssets(r.Context(), rp.ID, deref(params.Prefix), deref(params.After), limit)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	page := apigen.AssetPage{Items: make([]apigen.Asset, 0, len(as))}
	for _, a := range as {
		page.Items = append(page.Items, s.assetToAPI(r, a))
	}
	if len(as) == limit {
		page.Next = &as[len(as)-1].Path
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (s *Server) BrowseRepository(w http.ResponseWriter, r *http.Request, name string, params apigen.BrowseRepositoryParams) {
	rp, ok := s.requireRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	dir := deref(params.Path)
	if dir != "" && !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	entries, err := s.Store.Browse(r.Context(), rp.ID, strings.TrimPrefix(dir, "/"), 2000)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.BrowseEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, apigen.BrowseEntry{Name: e.Name, Path: e.Path, IsDir: e.IsDir, AssetId: e.AssetID, Size: e.Size})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) ListRepositoryComponents(w http.ResponseWriter, r *http.Request, name string, params apigen.ListRepositoryComponentsParams) {
	rp, ok := s.requireRepo(w, r, name, authz.Read)
	if !ok {
		return
	}
	cs, err := s.Store.SearchComponents(r.Context(), store.ComponentQuery{
		RepositoryIDs: []string{rp.ID}, Name: deref(params.Q), Limit: deref(params.Limit), Offset: deref(params.Offset),
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.Component, 0, len(cs))
	for _, c := range cs {
		out = append(out, s.componentToAPI(c))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) UploadComponent(w http.ResponseWriter, r *http.Request, name string) {
	rp, ok := s.requireRepo(w, r, name, authz.Write)
	if !ok {
		return
	}
	h, _ := s.Formats.Get(rp.Format)
	up, ok := h.(format.Uploader)
	if !ok {
		s.writeErr(w, errBad("format "+rp.Format+" does not support API uploads; use its native client"))
		return
	}
	if !rp.IsHosted() {
		s.writeErr(w, errBad("uploads require a hosted repository"))
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.writeErr(w, errBad("invalid multipart form: "+err.Error()))
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck
	f, fh, err := r.FormFile("file")
	if err != nil {
		s.writeErr(w, errBad("file is required"))
		return
	}
	defer f.Close()
	fields := map[string]string{}
	for k, v := range r.MultipartForm.Value {
		if len(v) > 0 {
			fields[k] = v[0]
		}
	}
	assets, err := up.Upload(r.Context(), rp, &format.Upload{File: f, Header: fh, Fields: fields, Uploader: principal(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]apigen.Asset, 0, len(assets))
	for _, a := range assets {
		out = append(out, s.assetToAPI(r, a))
	}
	s.audit(r, "component.upload", rp.Name, map[string]string{"file": fh.Filename})
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *Server) assetWithRepo(w http.ResponseWriter, r *http.Request, id string, action authz.Action) (*store.Asset, *repo.Repository, bool) {
	a, err := s.Store.GetAssetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			err = store.ErrNotFound
		}
		s.writeErr(w, err)
		return nil, nil, false
	}
	rp, ok := s.requireRepo(w, r, a.Repository, action)
	return a, rp, ok
}

func (s *Server) GetAsset(w http.ResponseWriter, r *http.Request, id string) {
	a, _, ok := s.assetWithRepo(w, r, id, authz.Read)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.assetToAPI(r, a))
}

func (s *Server) DeleteAsset(w http.ResponseWriter, r *http.Request, id string) {
	a, _, ok := s.assetWithRepo(w, r, id, authz.Delete)
	if !ok {
		return
	}
	if _, err := s.Repos.Delete(r.Context(), a.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, "asset.delete", a.Repository+"/"+a.Path, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DownloadAsset(w http.ResponseWriter, r *http.Request, id string) {
	a, rp, ok := s.assetWithRepo(w, r, id, authz.Read)
	if !ok {
		return
	}
	fn := a.Path
	if i := strings.LastIndex(fn, "/"); i >= 0 {
		fn = fn[i+1:]
	}
	s.Repos.Serve(w, r, rp, a, repo.ServeOptions{Filename: fn})
}

func (s *Server) componentWithRepo(w http.ResponseWriter, r *http.Request, id string, action authz.Action) (*store.Component, bool) {
	c, err := s.Store.GetComponent(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			err = store.ErrNotFound
		}
		s.writeErr(w, err)
		return nil, false
	}
	_, ok := s.requireRepo(w, r, c.Repository, action)
	return c, ok
}

func (s *Server) GetComponent(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.componentWithRepo(w, r, id, authz.Read)
	if !ok {
		return
	}
	as, err := s.Store.ListComponentAssets(r.Context(), c.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := apigen.ComponentDetail{Component: s.componentToAPI(c), Assets: make([]apigen.Asset, 0, len(as))}
	for _, a := range as {
		out.Assets = append(out.Assets, s.assetToAPI(r, a))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) DeleteComponent(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.componentWithRepo(w, r, id, authz.Delete)
	if !ok {
		return
	}
	as, err := s.Store.ListComponentAssets(r.Context(), c.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	for _, a := range as {
		if _, err := s.Repos.Delete(r.Context(), a.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
			s.writeErr(w, err)
			return
		}
	}
	s.audit(r, "component.delete", c.Repository+"/"+c.Name+"@"+c.Version, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) SearchComponents(w http.ResponseWriter, r *http.Request, params apigen.SearchComponentsParams) {
	ctx := r.Context()
	rs, err := s.Store.ListRepositories(ctx)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	ids := []string{}
	for _, x := range rs {
		if params.Repository != nil && *params.Repository != "" && x.Name != *params.Repository {
			continue
		}
		if s.Authz.Can(ctx, principal(r), authz.Read, authz.Target{Name: x.Name, AnonymousRead: x.AnonymousRead}) {
			ids = append(ids, x.ID)
		}
	}
	out := []apigen.Component{}
	if len(ids) > 0 {
		cs, err := s.Store.SearchComponents(ctx, store.ComponentQuery{
			RepositoryIDs: ids, Format: deref(params.Format), Name: deref(params.Q), Version: deref(params.Version),
			Limit: deref(params.Limit), Offset: deref(params.Offset),
		})
		if err != nil {
			s.writeErr(w, err)
			return
		}
		for _, c := range cs {
			out = append(out, s.componentToAPI(c))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
