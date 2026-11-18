package secrets

import (
	"errors"
	"strings"
	"testing"
)

const (
	k1 = "first-key-material-0123456789abcdef"
	k2 = "second-key-material-0123456789abcdef"
)

func TestSealOpen(t *testing.T) {
	b, err := New(k1)
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Seal("hunter2")
	if err != nil || !IsSealed(s) || strings.Contains(s, "hunter2") {
		t.Fatalf("seal: %q %v", s, err)
	}
	if again, _ := b.Seal(s); again != s {
		t.Fatal("sealing a sealed value must be a no-op")
	}
	if pt, err := b.Open(s); err != nil || pt != "hunter2" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if pt, _ := b.Open("plain"); pt != "plain" {
		t.Fatal("plaintext must pass through Open")
	}
	if e, _ := b.Seal(""); e != "" {
		t.Fatal("empty stays empty")
	}
	// Tampering is detected.
	bad := s[:len(s)-2] + "AA"
	if _, err := b.Open(bad); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func TestRotation(t *testing.T) {
	old, _ := New(k1)
	sealed, _ := old.Seal("token")

	other, _ := New(k2)
	if _, err := other.Open(sealed); !errors.Is(err, ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
	rotated, _ := New(k2, k1)
	if pt, err := rotated.Open(sealed); err != nil || pt != "token" {
		t.Fatalf("open with previous key: %q %v", pt, err)
	}
	if !rotated.NeedsReseal(sealed) || !rotated.NeedsReseal("plaintext") || rotated.NeedsReseal("") {
		t.Fatal("NeedsReseal wrong")
	}
	re, err := rotated.Reseal(sealed)
	if err != nil || rotated.NeedsReseal(re) {
		t.Fatalf("reseal: %v", err)
	}
	if _, err := New("short"); err == nil {
		t.Fatal("short key accepted")
	}
}
