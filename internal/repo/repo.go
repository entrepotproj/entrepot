// Package repo provides the repository service: typed repository
// configuration, asset storage (blob ingest + metadata) and serving.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/geoffo-dev/package-repository/internal/auth"
	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/storage"
	"github.com/geoffo-dev/package-repository/internal/store"
	"github.com/geoffo-dev/package-repository/internal/usage"
)

// UsageRepo identifies rp for the usage recorder.
func UsageRepo(rp *Repository) usage.Repo {
	return usage.Repo{ID: rp.ID, Name: rp.Name, Format: rp.Format}
}

const (
	KindHosted = "hosted"
	KindProxy  = "proxy"
	KindGroup  = "group"
)

// Config is the typed form of repositories.config.
type Config struct {
	Proxy   *ProxyConfig   `json:"proxy,omitempty"`
	Hosted  *HostedConfig  `json:"hosted,omitempty"`
	Group   *GroupConfig   `json:"group,omitempty"`
	Scan    *ScanConfig    `json:"scan,omitempty"`
	Cleanup *CleanupConfig `json:"cleanup,omitempty"`
}

// ScanConfig selects scanners and the download policy for a repository.
type ScanConfig struct {
	Scanners []string `json:"scanners,omitempty"`
	// OnUpload / OnProxyFetch default to true when nil.
	OnUpload     *bool `json:"onUpload,omitempty"`
	OnProxyFetch *bool `json:"onProxyFetch,omitempty"`
	// Mode is off, warn or quarantine (default warn when scanners are set).
	Mode string `json:"mode,omitempty"`
	// SeverityThreshold for quarantine: critical, high (default), medium, low.
	SeverityThreshold string `json:"severityThreshold,omitempty"`
	// BlockUntilScanned blocks downloads until the first scan completes.
	BlockUntilScanned bool `json:"blockUntilScanned,omitempty"`
	// Distro qualifies Apt/Yum packages for vulnerability matching (debian-12).
	Distro string `json:"distro,omitempty"`
}

// Enabled reports whether any scanner is configured and mode is not off.
func (c *ScanConfig) Enabled() bool {
	return c != nil && len(c.Scanners) > 0 && c.EffectiveMode() != "off"
}

func (c *ScanConfig) EffectiveMode() string {
	if c == nil || c.Mode == "" {
		return "warn"
	}
	return c.Mode
}

func (c *ScanConfig) Threshold() string {
	if c == nil || c.SeverityThreshold == "" {
		return "high"
	}
	return c.SeverityThreshold
}

func (c *ScanConfig) ScanOnUpload() bool { return c != nil && (c.OnUpload == nil || *c.OnUpload) }
func (c *ScanConfig) ScanOnProxyFetch() bool {
	return c != nil && (c.OnProxyFetch == nil || *c.OnProxyFetch)
}

// CleanupConfig lists the cleanup policies applied to a repository.
type CleanupConfig struct {
	Policies []string `json:"policies,omitempty"`
}

type ProxyConfig struct {
	// RemoteURL of the upstream, e.g. https://pypi.org, https://registry.npmjs.org,
	// https://registry-1.docker.io.
	RemoteURL string `json:"remoteUrl"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	// MetadataTTLSeconds: how long index/metadata documents are cached before
	// revalidation. Default 3600.
	MetadataTTLSeconds int `json:"metadataTtlSeconds,omitempty"`
	// ContentTTLSeconds: how long artifact content is cached before
	// revalidation. 0 (default) means artifacts are immutable and never
	// revalidated.
	ContentTTLSeconds int `json:"contentTtlSeconds,omitempty"`
	// NegativeCacheTTLSeconds: how long upstream 404s are remembered. Default 300.
	NegativeCacheTTLSeconds int `json:"negativeCacheTtlSeconds,omitempty"`
	// RoutingRule names a routing rule restricting what is fetched upstream.
	RoutingRule string `json:"routingRule,omitempty"`
}

func (p *ProxyConfig) MetadataTTL() time.Duration {
	if p == nil || p.MetadataTTLSeconds == 0 {
		return time.Hour
	}
	return time.Duration(p.MetadataTTLSeconds) * time.Second
}

// ContentTTL returns -1 for "never expires".
func (p *ProxyConfig) ContentTTL() time.Duration {
	if p == nil || p.ContentTTLSeconds <= 0 {
		return -1
	}
	return time.Duration(p.ContentTTLSeconds) * time.Second
}

func (p *ProxyConfig) NegativeTTL() time.Duration {
	if p == nil || p.NegativeCacheTTLSeconds == 0 {
		return 5 * time.Minute
	}
	if p.NegativeCacheTTLSeconds < 0 {
		return 0
	}
	return time.Duration(p.NegativeCacheTTLSeconds) * time.Second
}

type HostedConfig struct {
	// AllowRedeploy permits overwriting an existing artifact/version.
	AllowRedeploy bool       `json:"allowRedeploy"`
	Apt           *AptConfig `json:"apt,omitempty"`
	Yum           *YumConfig `json:"yum,omitempty"`
}

// AptConfig describes the distributions a hosted Apt repository publishes.
type AptConfig struct {
	Distributions []AptDistribution `json:"distributions,omitempty"`
}

type AptDistribution struct {
	Name          string   `json:"name"`
	Components    []string `json:"components,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	Label         string   `json:"label,omitempty"`
}

// YumConfig configures repodata generation for hosted Yum repositories.
type YumConfig struct {
	// RepodataDepth is the directory depth at which repodata is generated.
	RepodataDepth int `json:"repodataDepth"`
}

type GroupConfig struct {
	Members []string `json:"members"`
	// PreferHosted (npm/PyPI; default true when nil): package names present
	// in any hosted member are never served from proxy members.
	PreferHosted *bool `json:"preferHosted,omitempty"`
}

// PrefersHosted reports the effective preferHosted setting.
func (g *GroupConfig) PrefersHosted() bool {
	return g != nil && (g.PreferHosted == nil || *g.PreferHosted)
}

// Repository is a store.Repository with parsed config.
type Repository struct {
	*store.Repository
	Cfg Config
}

func (r *Repository) IsProxy() bool  { return r.Kind == KindProxy }
func (r *Repository) IsHosted() bool { return r.Kind == KindHosted }
func (r *Repository) IsGroup() bool  { return r.Kind == KindGroup }

func (r *Repository) AllowRedeploy() bool {
	return r.Cfg.Hosted != nil && r.Cfg.Hosted.AllowRedeploy
}

// ParseConfig decodes and validates a repository's config for its kind.
func ParseConfig(kind string, raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, fmt.Errorf("invalid repository config: %w", err)
		}
	}
	switch kind {
	case KindProxy:
		if c.Proxy == nil || c.Proxy.RemoteURL == "" {
			return c, errors.New("proxy repositories require proxy.remoteUrl")
		}
	case KindGroup:
		if c.Group == nil || len(c.Group.Members) == 0 {
			return c, errors.New("group repositories require group.members")
		}
	case KindHosted:
		if c.Hosted == nil {
			c.Hosted = &HostedConfig{}
		}
	default:
		return c, fmt.Errorf("unknown repository kind %q", kind)
	}
	return c, nil
}

var (
	ErrNotFound = errors.New("not found")
	// ErrRedeploy is returned when overwriting is not permitted.
	ErrRedeploy = errors.New("artifact already exists and redeploy is disabled")
)

// Service is shared by format handlers and the management API.
type Service struct {
	Store  *store.Store
	blobs  *storage.Registry
	logger *slog.Logger
	// Secrets opens sealed values in repository config (proxy passwords).
	Secrets *secrets.Box
	// Usage records downloads, uploads and deletes (may be nil).
	Usage *usage.Recorder

	// QuarantineCheck, when set, is consulted before serving content. A
	// blocked asset is answered with 403 and the returned reason.
	QuarantineCheck func(ctx context.Context, rp *Repository, a *store.Asset) (blocked bool, reason string)

	hooksMu sync.RWMutex
	stored  []StoredHook

	mu    sync.RWMutex
	cache map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	repo    *Repository
	expires time.Time
}

func NewService(st *store.Store, blobs *storage.Registry, logger *slog.Logger) *Service {
	return &Service{Store: st, blobs: blobs, logger: logger, cache: map[string]cacheEntry{}, ttl: 5 * time.Second}
}

// StoredEvent describes an asset linked to a component that was just stored.
type StoredEvent struct {
	Repository *Repository
	Asset      *store.Asset
	// ComponentID of the asset's component.
	ComponentID string
	// Cached is true for content fetched from an upstream by a proxy.
	Cached bool
	// Changed is false when identical content was re-stored (no-op upload).
	Changed bool
}

// StoredHook is called synchronously after an asset with a component is
// stored. Hooks must be fast (enqueue work, do not perform it).
type StoredHook func(ctx context.Context, ev StoredEvent)

// OnComponentStored registers a hook (used by the scanning pipeline).
func (s *Service) OnComponentStored(h StoredHook) {
	s.hooksMu.Lock()
	s.stored = append(s.stored, h)
	s.hooksMu.Unlock()
}

func (s *Service) fireStored(ctx context.Context, ev StoredEvent) {
	s.hooksMu.RLock()
	hooks := s.stored
	s.hooksMu.RUnlock()
	for _, h := range hooks {
		h(ctx, ev)
	}
}

// uploaderJSON describes the request principal for assets.uploader.
func uploaderJSON(ctx context.Context, rp *Repository, cached bool) json.RawMessage {
	p := auth.FromContext(ctx)
	if cached {
		b, _ := json.Marshal(map[string]any{"kind": "proxy", "name": "proxy:" + rp.Name, "requestedBy": p.Name})
		return b
	}
	u := map[string]any{"kind": p.Kind, "name": p.Name}
	if p.UserID != "" {
		u["userId"] = p.UserID
	}
	if p.Kind == auth.KindGitLab {
		u["gitlab"] = p.Instance
		for k, v := range p.Claims {
			u[k] = v
		}
	}
	b, _ := json.Marshal(u)
	return b
}

// Get returns a repository by name (briefly cached).
func (s *Service) Get(ctx context.Context, name string) (*Repository, error) {
	s.mu.RLock()
	e, ok := s.cache[name]
	s.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.repo, nil
	}
	r, err := s.Store.GetRepository(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rp, err := s.wrap(r)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[name] = cacheEntry{repo: rp, expires: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return rp, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*Repository, error) {
	r, err := s.Store.GetRepositoryByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.wrap(r)
}

func (s *Service) wrap(r *store.Repository) (*Repository, error) {
	cfg, err := ParseConfig(r.Kind, r.Config)
	if err != nil {
		return nil, fmt.Errorf("repository %s: %w", r.Name, err)
	}
	if cfg.Proxy != nil && cfg.Proxy.Password != "" && s.Secrets != nil {
		pw, err := s.Secrets.Open(cfg.Proxy.Password)
		if err != nil {
			return nil, fmt.Errorf("repository %s: proxy password: %w", r.Name, err)
		}
		cfg.Proxy.Password = pw
	}
	return &Repository{Repository: r, Cfg: cfg}, nil
}

// Invalidate drops the cached copy of a repository.
func (s *Service) Invalidate(name string) {
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
}

// BlobStore returns the blob store backing rp.
func (s *Service) BlobStore(ctx context.Context, rp *Repository) (storage.BlobStore, error) {
	bs, err := s.Store.GetBlobStoreByID(ctx, rp.BlobStoreID)
	if err != nil {
		return nil, err
	}
	return s.blobs.Get(ctx, bs.ID, bs.Type, bs.Config)
}

// ComponentRef links an asset to a component (name + version).
type ComponentRef struct {
	Name    string
	Version string
	Attrs   json.RawMessage
}

// PutOptions describes an asset to store.
type PutOptions struct {
	Path           string
	Body           io.Reader
	ContentType    string
	ExpectedDigest storage.Digest
	Attrs          json.RawMessage
	CreatedBy      string
	Component      *ComponentRef
	// Cached marks content fetched from an upstream (proxy repositories).
	Cached bool
	// NoOverwrite rejects replacing an existing asset with different content
	// (returns ErrRedeploy).
	NoOverwrite bool
}

// Put ingests content into the repository's blob store and records the asset.
func (s *Service) Put(ctx context.Context, rp *Repository, o PutOptions) (*store.Asset, error) {
	bs, err := s.BlobStore(ctx, rp)
	if err != nil {
		return nil, err
	}
	d, size, err := bs.Ingest(ctx, o.Body, o.ExpectedDigest)
	if err != nil {
		return nil, err
	}
	return s.PutStored(ctx, rp, d, size, o)
}

// PutStored records an asset for content that is already in the blob store.
func (s *Service) PutStored(ctx context.Context, rp *Repository, d storage.Digest, size int64, o PutOptions) (*store.Asset, error) {
	var componentID *string
	if o.Component != nil {
		c, err := s.Store.UpsertComponent(ctx, rp.ID, o.Component.Name, o.Component.Version, o.Component.Attrs)
		if err != nil {
			return nil, err
		}
		componentID = &c.ID
	}
	var prevDigest string
	if componentID != nil {
		if prev, err := s.Store.GetAsset(ctx, rp.ID, o.Path); err == nil {
			prevDigest = prev.Digest
		}
	}
	a, err := s.Store.PutAsset(ctx, store.PutAssetParams{
		Uploader:     uploaderJSON(ctx, rp, o.Cached),
		RepositoryID: rp.ID,
		StoreID:      rp.BlobStoreID,
		Path:         o.Path,
		Digest:       d.String(),
		Size:         size,
		ContentType:  o.ContentType,
		Attrs:        o.Attrs,
		CreatedBy:    o.CreatedBy,
		ComponentID:  componentID,
		Cached:       o.Cached,
		NoOverwrite:  o.NoOverwrite,
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, ErrRedeploy
	}
	if err == nil && !o.Cached {
		s.Usage.Upload(ctx, UsageRepo(rp), usage.Asset{Path: a.Path, ComponentID: a.ComponentID, Bytes: a.Size})
	}
	if err == nil && componentID != nil {
		s.fireStored(ctx, StoredEvent{Repository: rp, Asset: a, ComponentID: *componentID, Cached: o.Cached,
			Changed: prevDigest != a.Digest})
	}
	return a, err
}

// PutBytes is a convenience wrapper for small in-memory content.
func (s *Service) PutBytes(ctx context.Context, rp *Repository, b []byte, o PutOptions) (*store.Asset, error) {
	o.Body = bytesReader(b)
	return s.Put(ctx, rp, o)
}

// GetAsset returns the asset at path or ErrNotFound.
func (s *Service) GetAsset(ctx context.Context, rp *Repository, path string) (*store.Asset, error) {
	a, err := s.Store.GetAsset(ctx, rp.ID, path)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	return a, err
}

// Open opens an asset's content.
func (s *Service) Open(ctx context.Context, rp *Repository, a *store.Asset) (storage.ReadSeekCloser, error) {
	bs, err := s.BlobStore(ctx, rp)
	if err != nil {
		return nil, err
	}
	d, err := storage.ParseDigest(a.Digest)
	if err != nil {
		return nil, err
	}
	rc, _, err := bs.Open(ctx, d)
	return rc, err
}

// ReadAll reads a (small) asset fully into memory.
func (s *Service) ReadAll(ctx context.Context, rp *Repository, a *store.Asset, limit int64) ([]byte, error) {
	rc, err := s.Open(ctx, rp, a)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if limit <= 0 {
		limit = 256 << 20
	}
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("asset %s exceeds %d bytes", a.Path, limit)
	}
	return b, nil
}

// ServeOptions tweak Serve behaviour.
type ServeOptions struct {
	// ContentType overrides the stored content type.
	ContentType string
	// Filename sets Content-Disposition: attachment.
	Filename string
	// NoRedirect disables presigned redirects (e.g. Docker manifests).
	NoRedirect bool
}

// Serve writes an asset to the response, supporting HEAD, Range and
// conditional requests. S3 stores configured for redirects answer with a 307.
func (s *Service) Serve(w http.ResponseWriter, r *http.Request, rp *Repository, a *store.Asset, o ServeOptions) {
	ctx := r.Context()
	ct := o.ContentType
	if ct == "" {
		ct = a.ContentType
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("ETag", `"`+a.Digest+`"`)
	h.Set("X-Checksum-Sha256", storage.Digest(a.Digest).Hex())
	if o.Filename != "" {
		h.Set("Content-Disposition", `attachment; filename="`+o.Filename+`"`)
	}
	if s.QuarantineCheck != nil {
		if blocked, reason := s.QuarantineCheck(ctx, rp, a); blocked {
			h.Del("ETag")
			h.Del("X-Checksum-Sha256")
			h.Del("Content-Disposition")
			h.Set("Content-Type", "text/plain; charset=utf-8")
			h.Set("X-Entrepot-Quarantined", "true")
			w.WriteHeader(http.StatusForbidden)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "quarantined by Entrepot: "+reason+"\n")
			}
			return
		}
	}
	go s.markDownloaded(a.ID)

	bs, err := s.BlobStore(ctx, rp)
	if err != nil {
		s.serveErr(w, err)
		return
	}
	d, err := storage.ParseDigest(a.Digest)
	if err != nil {
		s.serveErr(w, err)
		return
	}
	if r.Method == http.MethodHead {
		h.Set("Content-Length", strconv.FormatInt(a.Size, 10))
		h.Set("Last-Modified", a.UpdatedAt.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		return
	}
	s.Usage.Download(ctx, UsageRepo(rp), usage.Asset{Path: a.Path, ComponentID: a.ComponentID, Bytes: a.Size})
	if ps, ok := bs.(storage.Presigner); ok && !o.NoRedirect && a.Size > 1<<20 {
		if u, err := ps.PresignGet(ctx, d, 15*time.Minute); err == nil {
			http.Redirect(w, r, u, http.StatusTemporaryRedirect)
			return
		}
	}
	rc, _, err := bs.Open(ctx, d)
	if err != nil {
		s.serveErr(w, err)
		return
	}
	defer rc.Close()
	http.ServeContent(w, r, "", a.UpdatedAt, rc)
}

func (s *Service) markDownloaded(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Store.MarkDownloaded(ctx, id); err != nil {
		s.logger.Debug("mark downloaded", "err", err)
	}
}

func (s *Service) serveErr(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		s.logger.Error("asset blob missing from store", "err", err)
		http.Error(w, "content missing from blob store", http.StatusInternalServerError)
		return
	}
	s.logger.Error("serve asset", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// Delete removes an asset.
func (s *Service) Delete(ctx context.Context, assetID string) (*store.Asset, error) {
	a, err := s.Store.DeleteAsset(ctx, assetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err == nil && s.Usage != nil {
		if rp, gerr := s.Get(ctx, a.Repository); gerr == nil {
			s.Usage.Delete(ctx, UsageRepo(rp), usage.Asset{Path: a.Path, ComponentID: a.ComponentID, Bytes: a.Size})
		}
	}
	return a, err
}
