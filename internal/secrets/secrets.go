// Package secrets encrypts sensitive configuration values stored in Postgres
// (proxy passwords, S3 keys, scanner secrets, GitLab API tokens, signing
// keys).
//
// Sealed values are strings of the form "enc:v1:<kid>:<base64url(nonce|ct)>"
// encrypted with AES-256-GCM. The key ID lets several keys coexist during
// rotation: new values are sealed with the current key, and any configured
// previous key can still open old ones. Plain strings (written before
// encryption was enabled) are returned unchanged by Open and re-sealed by
// the startup migration.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const prefix = "enc:v1:"

// ErrNoKey is returned when a value was sealed with an unknown key.
var ErrNoKey = errors.New("secret was sealed with an unknown key")

type key struct {
	id   string
	aead cipher.AEAD
}

// Box seals and opens secret strings.
type Box struct {
	current key
	all     map[string]cipher.AEAD
}

// New derives a Box from the current key material and optional previous
// keys (for rotation). Key material may be any string of at least 32 bytes.
func New(current string, previous ...string) (*Box, error) {
	cur, err := deriveKey(current)
	if err != nil {
		return nil, err
	}
	b := &Box{current: cur, all: map[string]cipher.AEAD{cur.id: cur.aead}}
	for _, p := range previous {
		if p == "" {
			continue
		}
		k, err := deriveKey(p)
		if err != nil {
			return nil, fmt.Errorf("previous key: %w", err)
		}
		b.all[k.id] = k.aead
	}
	return b, nil
}

func deriveKey(material string) (key, error) {
	if len(material) < 32 {
		return key{}, errors.New("secrets key must be at least 32 bytes")
	}
	raw, err := hkdf.Key(sha256.New, []byte(material), nil, "entrepot secrets v1", 32)
	if err != nil {
		return key{}, err
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return key{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return key{}, err
	}
	id := sha256.Sum256(append([]byte("kid:"), raw...))
	return key{id: hex.EncodeToString(id[:4]), aead: aead}, nil
}

// IsSealed reports whether s is a sealed value.
func IsSealed(s string) bool { return strings.HasPrefix(s, prefix) }

// Seal encrypts s. Empty strings and already sealed values are returned as is.
func (b *Box) Seal(s string) (string, error) {
	if s == "" || IsSealed(s) {
		return s, nil
	}
	nonce := make([]byte, b.current.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := b.current.aead.Seal(nonce, nonce, []byte(s), []byte(b.current.id))
	return prefix + b.current.id + ":" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// MustSeal is Seal for callers that cannot handle the (practically
// impossible) entropy failure.
func (b *Box) MustSeal(s string) string {
	out, err := b.Seal(s)
	if err != nil {
		panic(err)
	}
	return out
}

// Open decrypts a sealed value. Unsealed strings are returned unchanged.
func (b *Box) Open(s string) (string, error) {
	if !IsSealed(s) {
		return s, nil
	}
	rest := strings.TrimPrefix(s, prefix)
	kid, data, ok := strings.Cut(rest, ":")
	if !ok {
		return "", errors.New("malformed sealed secret")
	}
	aead, ok := b.all[kid]
	if !ok {
		return "", ErrNoKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("malformed sealed secret: %w", err)
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("malformed sealed secret")
	}
	pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(kid))
	if err != nil {
		return "", fmt.Errorf("open secret: %w", err)
	}
	return string(pt), nil
}

// NeedsReseal reports whether s is plaintext or sealed with a previous key.
func (b *Box) NeedsReseal(s string) bool {
	if s == "" {
		return false
	}
	if !IsSealed(s) {
		return true
	}
	kid, _, _ := strings.Cut(strings.TrimPrefix(s, prefix), ":")
	return kid != b.current.id
}

// Reseal re-encrypts s with the current key (plaintext is sealed).
func (b *Box) Reseal(s string) (string, error) {
	if !b.NeedsReseal(s) {
		return s, nil
	}
	pt, err := b.Open(s)
	if err != nil {
		return "", err
	}
	return b.Seal(pt)
}
