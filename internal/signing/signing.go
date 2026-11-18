// Package signing manages per-repository OpenPGP signing keys for hosted
// Apt and Yum repositories.
//
// Each repository has at most one active key (table signing_keys). A key is
// generated lazily (RSA-4096, accepted by every apt/gpgv and dnf/librepo
// release in use) the first time the repository's metadata is signed, and
// can be rotated or replaced by an imported key through the management API.
// Private keys are stored armored and sealed with internal/secrets; opened
// keys are cached in memory and the cache entry is revalidated against the
// active fingerprint on every use, so a rotation on one replica takes
// effect on all of them immediately.
package signing

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// ErrInvalidKey is returned when an imported key cannot be used for signing.
var ErrInvalidKey = errors.New("invalid signing key")

// cacheTTL bounds how long an opened private key stays in memory.
const cacheTTL = 10 * time.Minute

// Service creates, rotates and uses repository signing keys.
type Service struct {
	Store   *store.Store
	Secrets *secrets.Box
	// RSABits is the size of generated keys (default 4096).
	RSABits int

	mu    sync.Mutex
	cache map[string]cachedKey
}

type cachedKey struct {
	key    *Key
	opened time.Time
}

func New(st *store.Store, box *secrets.Box) *Service {
	return &Service{Store: st, Secrets: box, cache: map[string]cachedKey{}}
}

// Key is an opened repository signing key.
type Key struct {
	ID           string
	RepositoryID string
	Fingerprint  string
	// Algorithm describes the primary key, e.g. "rsa4096" or "ed25519".
	Algorithm string
	// PublicArmored is the ASCII-armored public key.
	PublicArmored string
	CreatedAt     time.Time

	entity *openpgp.Entity
}

// PublicBinary returns the public key in binary OpenPGP form (suitable for
// /usr/share/keyrings/*.gpg and apt's signed-by=).
func (k *Key) PublicBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := k.entity.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Entity exposes the OpenPGP entity (for tests and verification).
func (k *Key) Entity() *openpgp.Entity { return k.entity }

func signConfig() *packet.Config {
	no := false
	return &packet.Config{DefaultHash: crypto.SHA256, NonDeterministicSignaturesViaNotation: &no}
}

func (s *Service) bits() int {
	if s.RSABits > 0 {
		return s.RSABits
	}
	return 4096
}

// ActiveKey returns the repository's active key, creating one on first use.
func (s *Service) ActiveKey(ctx context.Context, repoID string) (*Key, error) {
	fp, err := s.Store.ActiveSigningKeyFingerprint(ctx, repoID)
	switch {
	case err == nil:
		if k := s.cached(repoID, fp); k != nil {
			return k, nil
		}
		return s.load(ctx, repoID)
	case errors.Is(err, store.ErrNotFound):
		return s.create(ctx, repoID)
	default:
		return nil, err
	}
}

func (s *Service) cached(repoID, fp string) *Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cache[repoID]
	if !ok || c.key.Fingerprint != fp || time.Since(c.opened) > cacheTTL {
		return nil
	}
	return c.key
}

func (s *Service) remember(k *Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]cachedKey{}
	}
	now := time.Now()
	for id, c := range s.cache {
		if now.Sub(c.opened) > cacheTTL {
			delete(s.cache, id)
		}
	}
	s.cache[k.RepositoryID] = cachedKey{key: k, opened: now}
}

func (s *Service) forget(repoID string) {
	s.mu.Lock()
	delete(s.cache, repoID)
	s.mu.Unlock()
}

func (s *Service) load(ctx context.Context, repoID string) (*Key, error) {
	row, err := s.Store.GetActiveSigningKey(ctx, repoID)
	if err != nil {
		return nil, err
	}
	k, err := s.open(row)
	if err != nil {
		return nil, err
	}
	s.remember(k)
	return k, nil
}

func (s *Service) open(row *store.SigningKey) (*Key, error) {
	armored := row.PrivateSealed
	if s.Secrets != nil {
		var err error
		if armored, err = s.Secrets.Open(row.PrivateSealed); err != nil {
			return nil, fmt.Errorf("open signing key: %w", err)
		}
	}
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil || len(el) == 0 {
		return nil, fmt.Errorf("parse signing key %s: %v", row.Fingerprint, err)
	}
	return &Key{
		ID: row.ID, RepositoryID: row.RepositoryID, Fingerprint: row.Fingerprint,
		Algorithm: algorithm(el[0].PrimaryKey), PublicArmored: row.PublicArmored,
		CreatedAt: row.CreatedAt, entity: el[0],
	}, nil
}

func (s *Service) create(ctx context.Context, repoID string) (*Key, error) {
	unlock, err := s.Store.AdvisoryLock(ctx, "signing-key:"+repoID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := s.Store.ActiveSigningKeyFingerprint(ctx, repoID); err == nil {
		return s.load(ctx, repoID) // created concurrently
	}
	e, err := s.generate(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, repoID, e, false)
}

func (s *Service) generate(ctx context.Context, repoID string) (*openpgp.Entity, error) {
	r, err := s.Store.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return nil, err
	}
	cfg := &packet.Config{
		Algorithm:                           packet.PubKeyAlgoRSA,
		RSABits:                             s.bits(),
		DefaultHash:                         crypto.SHA256,
		InsecureGenerateNonCriticalKeyFlags: true,
	}
	e, err := openpgp.NewEntity("Entrepot "+r.Name, "repository signing key", "", cfg)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return e, nil
}

func (s *Service) save(ctx context.Context, repoID string, e *openpgp.Entity, replace bool) (*Key, error) {
	var priv bytes.Buffer
	w, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	pub, err := armorPublic(e)
	if err != nil {
		return nil, err
	}
	sealed := priv.String()
	if s.Secrets != nil {
		if sealed, err = s.Secrets.Seal(sealed); err != nil {
			return nil, err
		}
	}
	row, err := s.Store.CreateSigningKey(ctx, &store.SigningKey{
		RepositoryID: repoID, Fingerprint: fingerprint(e), PublicArmored: pub, PrivateSealed: sealed,
	}, replace)
	if err != nil {
		return nil, err
	}
	k := &Key{
		ID: row.ID, RepositoryID: repoID, Fingerprint: row.Fingerprint, Algorithm: algorithm(e.PrimaryKey),
		PublicArmored: pub, CreatedAt: row.CreatedAt, entity: e,
	}
	s.remember(k)
	return k, nil
}

// Rotate replaces the active key with a newly generated one.
func (s *Service) Rotate(ctx context.Context, repoID string) (*Key, error) {
	e, err := s.generate(ctx, repoID)
	if err != nil {
		return nil, err
	}
	s.forget(repoID)
	return s.save(ctx, repoID, e, true)
}

// Import replaces the active key with an armored OpenPGP private key,
// decrypting it with passphrase when it is protected.
func (s *Service) Import(ctx context.Context, repoID, armoredPrivate, passphrase string) (*Key, error) {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivate))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one key, got %d", ErrInvalidKey, len(el))
	}
	e := el[0]
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("%w: not a private key (export it with gpg --armor --export-secret-keys)", ErrInvalidKey)
	}
	if encrypted(e) {
		if passphrase == "" {
			return nil, fmt.Errorf("%w: the key is passphrase protected; supply passphrase", ErrInvalidKey)
		}
		if err := e.DecryptPrivateKeys([]byte(passphrase)); err != nil {
			return nil, fmt.Errorf("%w: cannot decrypt the key: %v", ErrInvalidKey, err)
		}
	}
	sk, ok := e.SigningKey(time.Now())
	if !ok || sk.PrivateKey == nil || sk.PrivateKey.Dummy() || sk.PrivateKey.Encrypted {
		return nil, fmt.Errorf("%w: the key has no usable (unexpired, unrevoked) signing key", ErrInvalidKey)
	}
	// Prove it can sign.
	if err := openpgp.DetachSign(io.Discard, e, strings.NewReader("probe"), signConfig()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	s.forget(repoID)
	return s.save(ctx, repoID, e, true)
}

func encrypted(e *openpgp.Entity) bool {
	if e.PrivateKey != nil && e.PrivateKey.Encrypted {
		return true
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// PublicKey returns the active ASCII-armored public key.
func (s *Service) PublicKey(ctx context.Context, repoID string) (string, error) {
	k, err := s.ActiveKey(ctx, repoID)
	if err != nil {
		return "", err
	}
	return k.PublicArmored, nil
}

// ClearSign returns data as a cleartext-signed message (Apt InRelease).
func (s *Service) ClearSign(ctx context.Context, repoID string, data []byte) ([]byte, error) {
	k, err := s.ActiveKey(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return k.ClearSign(data)
}

// DetachSign returns a detached signature of data, armored or binary
// (Apt Release.gpg is binary or armored; Yum repomd.xml.asc is armored).
func (s *Service) DetachSign(ctx context.Context, repoID string, data []byte, armored bool) ([]byte, error) {
	k, err := s.ActiveKey(ctx, repoID)
	if err != nil {
		return nil, err
	}
	return k.DetachSign(data, armored)
}

// ClearSign signs data with the key.
func (k *Key) ClearSign(data []byte) ([]byte, error) {
	sk, ok := k.entity.SigningKey(time.Now())
	if !ok || sk.PrivateKey == nil {
		return nil, errors.New("signing key has no usable private signing key")
	}
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, sk.PrivateKey, signConfig())
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DetachSign signs data with the key.
func (k *Key) DetachSign(data []byte, armored bool) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if armored {
		err = openpgp.ArmoredDetachSign(&buf, k.entity, bytes.NewReader(data), signConfig())
	} else {
		err = openpgp.DetachSign(&buf, k.entity, bytes.NewReader(data), signConfig())
	}
	if err != nil {
		return nil, err
	}
	if armored && !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func armorPublic(e *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	if err := e.Serialize(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	buf.WriteByte('\n')
	return buf.String(), nil
}

func fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(fmt.Sprintf("%x", e.PrimaryKey.Fingerprint))
}

func algorithm(pk *packet.PublicKey) string {
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		bits, _ := pk.BitLength()
		return fmt.Sprintf("rsa%d", bits)
	case packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519:
		return "ed25519"
	case packet.PubKeyAlgoEd448:
		return "ed448"
	case packet.PubKeyAlgoECDSA:
		if c, err := pk.Curve(); err == nil {
			return "ecdsa-" + string(c)
		}
		return "ecdsa"
	case packet.PubKeyAlgoDSA:
		bits, _ := pk.BitLength()
		return fmt.Sprintf("dsa%d", bits)
	default:
		return fmt.Sprintf("openpgp-%d", pk.PubKeyAlgo)
	}
}
