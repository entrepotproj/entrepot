// Package store is the Postgres persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
	ErrInUse    = errors.New("still in use")
	ErrInvalid  = errors.New("invalid")
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// querier is satisfied by both the pool and a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

// mapErr converts pgx/Postgres errors to package sentinel errors.
func mapErr(err error, what string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%s: %w", what, ErrConflict)
		case "23503":
			return fmt.Errorf("%s: %w (%s)", what, ErrInUse, pgErr.Detail)
		case "23514", "22P02":
			return fmt.Errorf("%s: %w: %s", what, ErrInvalid, pgErr.Message)
		}
	}
	return fmt.Errorf("%s: %w", what, err)
}

type pgxTx = pgx.Tx

var errNoRows = pgx.ErrNoRows

func isNotNullViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23502"
}
