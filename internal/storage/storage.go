// Package storage implements content-addressed blob stores.
//
// A BlobStore keeps immutable blobs keyed by their sha256 digest, plus a
// scratch area ("temp" objects) used for multi-request uploads such as
// chunked Docker pushes. Drivers:
//
//   - file: a directory on a mounted volume. Covers Kubernetes PVCs backed by
//     EBS (ReadWriteOnce), EFS (ReadWriteMany), NFS, hostPath, etc.
//   - s3:   any S3-compatible object store (AWS S3, MinIO, Ceph RGW, ...).
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound       = errors.New("blob not found")
	ErrDigestMismatch = errors.New("digest mismatch")
	ErrInvalidDigest  = errors.New("invalid digest")
)

// Digest is an OCI-style digest string: "sha256:<64 hex>".
type Digest string

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func ParseDigest(s string) (Digest, error) {
	if !digestRE.MatchString(s) {
		return "", fmt.Errorf("%w: %q", ErrInvalidDigest, s)
	}
	return Digest(s), nil
}

func (d Digest) String() string { return string(d) }
func (d Digest) Hex() string    { return strings.TrimPrefix(string(d), "sha256:") }

// DigestBytes returns the sha256 digest of b.
func DigestBytes(b []byte) Digest {
	sum := sha256.Sum256(b)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// Info describes a stored blob.
type Info struct {
	Digest  Digest
	Size    int64
	ModTime time.Time
}

// ReadSeekCloser is returned by Open so callers can serve Range requests.
type ReadSeekCloser interface {
	io.ReadSeeker
	io.Closer
}

// BlobStore is implemented by each storage driver.
type BlobStore interface {
	// Type returns the driver name ("file", "s3").
	Type() string
	// Ingest stores everything read from r. If expected is non-empty and the
	// content does not hash to it, ErrDigestMismatch is returned and nothing
	// is stored. Ingesting content that already exists is cheap and safe.
	Ingest(ctx context.Context, r io.Reader, expected Digest) (Digest, int64, error)
	Open(ctx context.Context, d Digest) (ReadSeekCloser, Info, error)
	Stat(ctx context.Context, d Digest) (Info, error)
	Delete(ctx context.Context, d Digest) error
	// Walk visits every blob in the store.
	Walk(ctx context.Context, fn func(Info) error) error

	// Temp objects: named, mutable scratch objects for upload sessions.
	PutTemp(ctx context.Context, key string, r io.Reader) (int64, error)
	OpenTemp(ctx context.Context, key string) (io.ReadCloser, error)
	DeleteTempPrefix(ctx context.Context, prefix string) error

	// Check verifies the store is reachable and writable.
	Check(ctx context.Context) error
}

// Presigner is optionally implemented by drivers that can hand out direct
// download URLs (S3), letting the server redirect large downloads.
type Presigner interface {
	PresignGet(ctx context.Context, d Digest, ttl time.Duration) (string, error)
}

// hashingReader computes sha256 and size while reading.
type hashingReader struct {
	r    io.Reader
	h    interface{ Sum([]byte) []byte }
	w    io.Writer
	size int64
}

func newHashingReader(r io.Reader) *hashingReader {
	h := sha256.New()
	return &hashingReader{r: r, h: h, w: h}
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.w.Write(p[:n]) //nolint:errcheck // hash writes never fail
		h.size += int64(n)
	}
	return n, err
}

func (h *hashingReader) Digest() Digest {
	return Digest("sha256:" + hex.EncodeToString(h.h.Sum(nil)))
}

var tempKeyRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

func validTempKey(key string) error {
	if !tempKeyRE.MatchString(key) || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return fmt.Errorf("invalid temp key %q", key)
	}
	return nil
}
