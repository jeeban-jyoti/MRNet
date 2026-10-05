// Package registry is the global email registry: email -> user_id and home
// region, in a multi-region, strongly consistent database (CockroachDB).
// It is written only at signup, so it is the one place two regions can race
// on the same email and exactly one wins.
package registry

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const Schema = `
CREATE TABLE IF NOT EXISTS email_registry (
  email_norm  STRING PRIMARY KEY,
  user_id     UUID NOT NULL UNIQUE,
  home_region STRING NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

var (
	ErrTaken    = errors.New("email already registered")
	ErrNotFound = errors.New("email not registered")
)

type Entry struct {
	UserID     string
	HomeRegion string
}

type Registry struct{ DB *pgxpool.Pool }

func (r *Registry) Claim(ctx context.Context, emailNorm, userID, region string) error {
	_, err := r.DB.Exec(ctx, `INSERT INTO email_registry (email_norm, user_id, home_region) VALUES ($1,$2,$3)`, emailNorm, userID, region)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrTaken
	}
	return err
}

// Release undoes a claim when the rest of signup failed.
func (r *Registry) Release(ctx context.Context, emailNorm, userID string) error {
	_, err := r.DB.Exec(ctx, `DELETE FROM email_registry WHERE email_norm=$1 AND user_id=$2`, emailNorm, userID)
	return err
}

func (r *Registry) Lookup(ctx context.Context, emailNorm string) (*Entry, error) {
	var e Entry
	err := r.DB.QueryRow(ctx, `SELECT user_id::STRING, home_region FROM email_registry WHERE email_norm=$1`, emailNorm).Scan(&e.UserID, &e.HomeRegion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &e, err
}

func (r *Registry) HomeOf(ctx context.Context, userID string) (string, error) {
	var region string
	err := r.DB.QueryRow(ctx, `SELECT home_region FROM email_registry WHERE user_id=$1`, userID).Scan(&region)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return region, err
}
