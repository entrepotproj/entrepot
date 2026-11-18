package repo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/geoffo-dev/package-repository/internal/storage"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// GC removes unreferenced blobs older than grace from every blob store.
func (s *Service) GC(ctx context.Context, grace time.Duration) (int, error) {
	stores, err := s.Store.ListBlobStores(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, st := range stores {
		bs, err := s.blobs.Get(ctx, st.ID, st.Type, st.Config)
		if err != nil {
			s.logger.Warn("gc: open blob store", "store", st.Name, "err", err)
			continue
		}
		digests, err := s.Store.UnreferencedBlobs(ctx, st.ID, grace, 1000)
		if err != nil {
			return removed, err
		}
		for _, d := range digests {
			ok, err := s.Store.DeleteBlobRow(ctx, st.ID, d)
			if err != nil || !ok {
				continue
			}
			if err := bs.Delete(ctx, storage.Digest(d)); err != nil && !errors.Is(err, storage.ErrNotFound) {
				s.logger.Warn("gc: delete blob", "store", st.Name, "digest", d, "err", err)
				continue
			}
			removed++
		}
	}
	return removed, nil
}

// RunMaintenance periodically garbage collects blobs and stale uploads.
func (s *Service) RunMaintenance(ctx context.Context, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n, err := s.GC(ctx, time.Hour)
		if err != nil {
			logger.Warn("blob gc", "err", err)
		} else if n > 0 {
			logger.Info("blob gc", "removed", n)
		}
		s.cleanupUploads(ctx, logger)
	}
}

func (s *Service) cleanupUploads(ctx context.Context, logger *slog.Logger) {
	ups, err := s.Store.StaleDockerUploads(ctx, 24*time.Hour)
	if err != nil {
		logger.Warn("stale uploads", "err", err)
		return
	}
	for _, u := range ups {
		rp, err := s.GetByID(ctx, u.RepositoryID)
		if err == nil {
			if bs, err := s.BlobStore(ctx, rp); err == nil {
				_ = bs.DeleteTempPrefix(ctx, "uploads/"+u.ID)
			}
		}
		_ = s.Store.DeleteDockerUpload(ctx, u.ID)
	}
}
