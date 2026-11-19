package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenPrefix identifies Entrepot API tokens.
const TokenPrefix = "ent_"

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewAPIToken returns a new random token, its storage hash and a display hint.
func NewAPIToken() (token string, hash []byte, hint string, err error) {
	b := make([]byte, 40)
	max := big.NewInt(int64(len(base62)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", nil, "", err
		}
		b[i] = base62[n.Int64()]
	}
	token = TokenPrefix + string(b)
	return token, HashToken(token), token[:len(TokenPrefix)+4] + "…" + token[len(token)-4:], nil
}

// HashToken returns the SHA-256 of a token. Tokens have 238 bits of entropy,
// so a fast hash is appropriate (no need for bcrypt).
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Keys derives independent keys from the shared session secret.
type Keys struct {
	session  []byte
	registry []byte
}

func DeriveKeys(secret string) (*Keys, error) {
	if len(secret) < 32 {
		return nil, errors.New("session secret must be at least 32 bytes")
	}
	sess, err := hkdf.Key(sha256.New, []byte(secret), nil, "entrepot session v1", 32)
	if err != nil {
		return nil, err
	}
	reg, err := hkdf.Key(sha256.New, []byte(secret), nil, "entrepot registry token v1", 32)
	if err != nil {
		return nil, err
	}
	return &Keys{session: sess, registry: reg}, nil
}

// Session is the payload of the encrypted session cookie.
type Session struct {
	UserID string `json:"u,omitempty"`
	// Token is set for API-token logins (no OIDC), so the session carries
	// exactly the rights of that token.
	Token   string    `json:"t,omitempty"`
	Expires time.Time `json:"e"`
	// IDToken is kept (when small) for RP-initiated logout.
	IDTokenHint string `json:"i,omitempty"`
}

func (k *Keys) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.session)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts v (JSON) into a URL-safe string.
func (k *Keys) Seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	g, err := k.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, plain, nil)), nil
}

// Open decrypts a value produced by Seal.
func (k *Keys) Open(s string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	g, err := k.aead()
	if err != nil {
		return err
	}
	if len(raw) < g.NonceSize() {
		return errors.New("ciphertext too short")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

const registryIssuer = "entrepot-registry"

// RegistryAccess mirrors the Docker token spec "access" claim.
type RegistryAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type registryClaims struct {
	jwt.RegisteredClaims
	Principal *Principal       `json:"p"`
	Access    []RegistryAccess `json:"access,omitempty"`
}

// IssueRegistryToken mints a short-lived HS256 JWT for Docker clients that
// embeds the authenticated principal. Authorization is re-evaluated on every
// request, so the token only proves identity.
func (k *Keys) IssueRegistryToken(p *Principal, service string, access []RegistryAccess, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := registryClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    registryIssuer,
			Subject:   p.Name,
			Audience:  jwt.ClaimStrings{service},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Principal: p,
		Access:    access,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(k.registry)
}

func (k *Keys) parseRegistryToken(tok string) (*Principal, error) {
	var claims registryClaims
	_, err := jwt.ParseWithClaims(tok, &claims, func(t *jwt.Token) (any, error) {
		return k.registry, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(registryIssuer))
	if err != nil {
		return nil, fmt.Errorf("registry token: %w", err)
	}
	if claims.Principal == nil {
		return nil, errors.New("registry token: missing principal")
	}
	return claims.Principal, nil
}

// peekIssuer returns the unverified "iss" claim of a JWT, or "" if s is not a JWT.
func peekIssuer(s string) string {
	var claims jwt.RegisteredClaims
	_, _, err := jwt.NewParser().ParseUnverified(s, &claims)
	if err != nil {
		return ""
	}
	return claims.Issuer
}
