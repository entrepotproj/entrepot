package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileStore stores blobs on a local or mounted filesystem:
//
//	<root>/blobs/sha256/<aa>/<digest-hex>
//	<root>/temp/<key>
//	<root>/.ingest/<random>   (in-flight writes, renamed atomically)
type FileStore struct {
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, errors.New("file store: path is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"blobs/sha256", "temp", ".ingest"} {
		if err := os.MkdirAll(filepath.Join(abs, d), 0o750); err != nil {
			return nil, fmt.Errorf("file store: %w", err)
		}
	}
	return &FileStore{root: abs}, nil
}

func (s *FileStore) Type() string { return "file" }

func (s *FileStore) blobPath(d Digest) string {
	h := d.Hex()
	return filepath.Join(s.root, "blobs", "sha256", h[:2], h)
}

func (s *FileStore) Ingest(ctx context.Context, r io.Reader, expected Digest) (Digest, int64, error) {
	tmp, err := os.CreateTemp(filepath.Join(s.root, ".ingest"), "ingest-*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // no-op after rename

	hr := newHashingReader(ctxReader{ctx, r})
	if _, err := io.Copy(tmp, hr); err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	d := hr.Digest()
	if expected != "" && d != expected {
		return "", 0, fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expected, d)
	}
	dst := s.blobPath(d)
	if _, err := os.Stat(dst); err == nil {
		return d, hr.size, nil // already present
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return "", 0, err
	}
	return d, hr.size, nil
}

func (s *FileStore) Open(_ context.Context, d Digest) (ReadSeekCloser, Info, error) {
	f, err := os.Open(s.blobPath(d))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, Info{}, err
	}
	return f, Info{Digest: d, Size: st.Size(), ModTime: st.ModTime()}, nil
}

func (s *FileStore) Stat(_ context.Context, d Digest) (Info, error) {
	st, err := os.Stat(s.blobPath(d))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Info{}, ErrNotFound
		}
		return Info{}, err
	}
	return Info{Digest: d, Size: st.Size(), ModTime: st.ModTime()}, nil
}

func (s *FileStore) Delete(_ context.Context, d Digest) error {
	err := os.Remove(s.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileStore) Walk(ctx context.Context, fn func(Info) error) error {
	base := filepath.Join(s.root, "blobs", "sha256")
	return filepath.WalkDir(base, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if de.IsDir() {
			return nil
		}
		d, perr := ParseDigest("sha256:" + de.Name())
		if perr != nil {
			return nil // ignore foreign files
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		return fn(Info{Digest: d, Size: info.Size(), ModTime: info.ModTime()})
	})
}

func (s *FileStore) tempPath(key string) (string, error) {
	if err := validTempKey(key); err != nil {
		return "", err
	}
	return filepath.Join(s.root, "temp", filepath.FromSlash(key)), nil
}

func (s *FileStore) PutTemp(ctx context.Context, key string, r io.Reader) (int64, error) {
	p, err := s.tempPath(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return 0, err
	}
	f, err := os.Create(p)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, ctxReader{ctx, r})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

func (s *FileStore) OpenTemp(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := s.tempPath(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (s *FileStore) DeleteTempPrefix(_ context.Context, prefix string) error {
	prefix = strings.TrimSuffix(prefix, "/")
	p, err := s.tempPath(prefix)
	if err != nil {
		return err
	}
	return os.RemoveAll(p)
}

func (s *FileStore) Check(_ context.Context) error {
	f, err := os.CreateTemp(filepath.Join(s.root, ".ingest"), "check-*")
	if err != nil {
		return fmt.Errorf("file store %s not writable: %w", s.root, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// ctxReader aborts long copies when the request context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
