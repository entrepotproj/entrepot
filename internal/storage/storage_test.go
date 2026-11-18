package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

func testStore(t *testing.T, s BlobStore) {
	ctx := context.Background()
	if err := s.Check(ctx); err != nil {
		t.Fatalf("check: %v", err)
	}
	content := []byte("hello blob store")
	want := DigestBytes(content)

	// Wrong expected digest stores nothing.
	other := DigestBytes([]byte("other"))
	if _, _, err := s.Ingest(ctx, bytes.NewReader(content), other); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	if _, err := s.Stat(ctx, want); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blob should not exist after mismatch: %v", err)
	}

	d, n, err := s.Ingest(ctx, bytes.NewReader(content), want)
	if err != nil || d != want || n != int64(len(content)) {
		t.Fatalf("ingest: %v %s %d", err, d, n)
	}
	// Idempotent.
	if d2, _, err := s.Ingest(ctx, bytes.NewReader(content), ""); err != nil || d2 != want {
		t.Fatalf("re-ingest: %v", err)
	}
	rc, info, err := s.Open(ctx, want)
	if err != nil || info.Size != int64(len(content)) {
		t.Fatalf("open: %v %+v", err, info)
	}
	if _, err := rc.Seek(6, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(rc)
	rc.Close()
	if string(rest) != "blob store" {
		t.Fatalf("seek+read got %q", rest)
	}
	var walked []Digest
	if err := s.Walk(ctx, func(i Info) error { walked = append(walked, i.Digest); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(walked) != 1 || walked[0] != want {
		t.Fatalf("walk: %v", walked)
	}

	// Temp objects.
	if _, err := s.PutTemp(ctx, "uploads/abc/0", strings.NewReader("part0")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutTemp(ctx, "uploads/abc/1", strings.NewReader("part1")); err != nil {
		t.Fatal(err)
	}
	r0, err := s.OpenTemp(ctx, "uploads/abc/1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r0)
	r0.Close()
	if string(b) != "part1" {
		t.Fatalf("temp got %q", b)
	}
	if _, err := s.PutTemp(ctx, "../escape", strings.NewReader("x")); err == nil {
		t.Fatal("expected invalid temp key error")
	}
	if err := s.DeleteTempPrefix(ctx, "uploads/abc/"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenTemp(ctx, "uploads/abc/0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("temp should be deleted: %v", err)
	}

	if err := s.Delete(ctx, want); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, want); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found after delete: %v", err)
	}
}

func TestFileStore(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

func TestS3Store(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	srv := httptest.NewServer(faker.Server())
	defer srv.Close()
	if err := backend.CreateBucket("entrepot"); err != nil {
		t.Fatal(err)
	}
	s, err := NewS3Store(context.Background(), S3Config{
		Bucket: "entrepot", Region: "us-east-1", Prefix: "blobs-test", Endpoint: srv.URL,
		ForcePathStyle: true, AccessKeyID: "test", SecretAccessKey: "test",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

func TestRegistryAllowedRoots(t *testing.T) {
	root := t.TempDir()
	r := NewRegistry([]string{root}, t.TempDir())
	if _, err := r.Build(context.Background(), "file", []byte(`{"path":"`+root+`/store"}`)); err != nil {
		t.Fatalf("path under root rejected: %v", err)
	}
	if _, err := r.Build(context.Background(), "file", []byte(`{"path":"/etc"}`)); err == nil {
		t.Fatal("path outside allowed roots accepted")
	}
	if _, err := r.Build(context.Background(), "file", []byte(`{"path":"`+root+`/../x"}`)); err == nil {
		t.Fatal("traversal outside allowed roots accepted")
	}
}
