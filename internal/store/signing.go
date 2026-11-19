package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SigningKey is an OpenPGP key used to sign a repository's metadata.
type SigningKey struct {
	ID            string
	RepositoryID  string
	Fingerprint   string
	PublicArmored string
	// PrivateSealed is the armored private key sealed with internal/secrets.
	PrivateSealed string
	Active        bool
	CreatedAt     time.Time
}

const signingKeySelect = `SELECT id, repository_id, fingerprint, public_armored, private_sealed, active, created_at FROM signing_keys`

func scanSigningKey(row interface{ Scan(...any) error }) (*SigningKey, error) {
	var k SigningKey
	err := row.Scan(&k.ID, &k.RepositoryID, &k.Fingerprint, &k.PublicArmored, &k.PrivateSealed, &k.Active, &k.CreatedAt)
	return &k, err
}

// GetActiveSigningKey returns the active signing key of a repository.
func (s *Store) GetActiveSigningKey(ctx context.Context, repoID string) (*SigningKey, error) {
	k, err := scanSigningKey(s.pool.QueryRow(ctx, signingKeySelect+` WHERE repository_id=$1 AND active`, repoID))
	return k, mapErr(err, "signing key")
}

// ActiveSigningKeyFingerprint returns the fingerprint of the active key
// without loading the (sealed) private key.
func (s *Store) ActiveSigningKeyFingerprint(ctx context.Context, repoID string) (string, error) {
	var fp string
	err := s.pool.QueryRow(ctx, `SELECT fingerprint FROM signing_keys WHERE repository_id=$1 AND active`, repoID).Scan(&fp)
	return fp, mapErr(err, "signing key")
}

// ListSigningKeys lists a repository's keys, newest first.
func (s *Store) ListSigningKeys(ctx context.Context, repoID string) ([]*SigningKey, error) {
	rows, err := s.pool.Query(ctx, signingKeySelect+` WHERE repository_id=$1 ORDER BY created_at DESC`, repoID)
	if err != nil {
		return nil, mapErr(err, "signing keys")
	}
	defer rows.Close()
	var out []*SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CreateSigningKey stores a new active key. With replace, the current
// active key (if any) is deactivated in the same transaction; without it,
// ErrConflict is returned when the repository already has an active key.
func (s *Store) CreateSigningKey(ctx context.Context, k *SigningKey, replace bool) (*SigningKey, error) {
	var id string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if replace {
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET active=false WHERE repository_id=$1 AND active`, k.RepositoryID); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `INSERT INTO signing_keys (repository_id, fingerprint, public_armored, private_sealed, active)
			VALUES ($1,$2,$3,$4,true) RETURNING id`, k.RepositoryID, k.Fingerprint, k.PublicArmored, k.PrivateSealed).Scan(&id)
	})
	if err != nil {
		return nil, mapErr(err, "create signing key")
	}
	return scanSigningKeyByID(ctx, s, id)
}

func scanSigningKeyByID(ctx context.Context, s *Store, id string) (*SigningKey, error) {
	k, err := scanSigningKey(s.pool.QueryRow(ctx, signingKeySelect+` WHERE id=$1`, id))
	return k, mapErr(err, "signing key")
}
