package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// FileConfig configures a filesystem blob store.
type FileConfig struct {
	Path string `json:"path"`
}

// Registry builds and caches BlobStore instances keyed by store ID. A store is
// rebuilt when its configuration changes.
type Registry struct {
	allowedRoots []string
	tempDir      string

	mu     sync.Mutex
	stores map[string]cached
}

type cached struct {
	fingerprint string
	store       BlobStore
}

func NewRegistry(allowedRoots []string, tempDir string) *Registry {
	return &Registry{allowedRoots: allowedRoots, tempDir: tempDir, stores: map[string]cached{}}
}

// Get returns the BlobStore for id, constructing it from typ/config if needed.
func (r *Registry) Get(ctx context.Context, id, typ string, config json.RawMessage) (BlobStore, error) {
	fp := typ + "|" + string(config)
	r.mu.Lock()
	if c, ok := r.stores[id]; ok && c.fingerprint == fp {
		r.mu.Unlock()
		return c.store, nil
	}
	r.mu.Unlock()

	s, err := r.Build(ctx, typ, config)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.stores[id] = cached{fingerprint: fp, store: s}
	r.mu.Unlock()
	return s, nil
}

// Forget drops a cached instance (e.g. after deleting the store).
func (r *Registry) Forget(id string) {
	r.mu.Lock()
	delete(r.stores, id)
	r.mu.Unlock()
}

// Build validates config and constructs a new store instance.
func (r *Registry) Build(ctx context.Context, typ string, config json.RawMessage) (BlobStore, error) {
	switch typ {
	case "file":
		var fc FileConfig
		if err := json.Unmarshal(config, &fc); err != nil {
			return nil, fmt.Errorf("file store config: %w", err)
		}
		if err := r.checkRoot(fc.Path); err != nil {
			return nil, err
		}
		return NewFileStore(fc.Path)
	case "s3":
		var sc S3Config
		if err := json.Unmarshal(config, &sc); err != nil {
			return nil, fmt.Errorf("s3 store config: %w", err)
		}
		return NewS3Store(ctx, sc, r.tempDir)
	default:
		return nil, fmt.Errorf("unknown blob store type %q", typ)
	}
}

func (r *Registry) checkRoot(p string) error {
	if p == "" {
		return fmt.Errorf("file store: path is required")
	}
	if len(r.allowedRoots) == 0 {
		return nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	for _, root := range r.allowedRoots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if abs == rootAbs || strings.HasPrefix(abs, rootAbs+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("file store path %q is outside storage.allowedRoots %v", p, r.allowedRoots)
}
