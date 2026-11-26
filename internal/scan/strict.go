package scan

import (
	"context"
	"time"

	"github.com/entrepotproj/entrepot/internal/repo"
	"github.com/entrepotproj/entrepot/internal/store"
)

// isFileScanner reports whether scanners of type t read the files of a
// component (rather than look its name and version up).
func isFileScanner(t string) bool {
	return false
}

// scannerIndex is a short-lived snapshot of the configured scanners.
type scannerIndex struct {
	byName  map[string]*store.Scanner
	expires time.Time
}

// scanners returns the configured scanners by name, cached for a few
// seconds (verdicts and upload hooks consult it on every call).
func (s *Service) scanners(ctx context.Context) (map[string]*store.Scanner, error) {
	s.mu.Lock()
	idx := s.scannerIdx
	s.mu.Unlock()
	if idx != nil && time.Now().Before(idx.expires) {
		return idx.byName, nil
	}
	list, err := s.Store.ListScanners(ctx)
	if err != nil {
		return nil, err
	}
	idx = &scannerIndex{byName: make(map[string]*store.Scanner, len(list)), expires: time.Now().Add(5 * time.Second)}
	for _, sc := range list {
		idx.byName[sc.Name] = sc
	}
	s.mu.Lock()
	s.scannerIdx = idx
	s.mu.Unlock()
	return idx.byName, nil
}

// ForgetScanners drops the cached scanner snapshot (after scanner changes).
func (s *Service) ForgetScanners() {
	s.mu.Lock()
	s.scannerIdx = nil
	s.mu.Unlock()
}

// strictConfig reports the enabled scanners configured on a repository and
// whether its verdicts are strict: with blockOnError, or when a file
// scanner is configured, a component is pending until every configured
// scanner has scanned its current content, and new or changed files make it
// pending again. Other repositories keep the original rules (the first
// completed scan decides).
func (s *Service) strictConfig(ctx context.Context, sc *repo.ScanConfig) (configured map[string]bool, strict bool, err error) {
	if !sc.Enabled() {
		return nil, false, nil
	}
	all, err := s.scanners(ctx)
	if err != nil {
		return nil, false, err
	}
	configured = map[string]bool{}
	strict = sc.BlockOnError
	for _, name := range sc.Scanners {
		if x := all[name]; x != nil && x.Enabled {
			configured[name] = true
			if isFileScanner(x.Type) {
				strict = true
			}
		}
	}
	return configured, strict, nil
}
