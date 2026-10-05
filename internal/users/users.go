// Package users is the credential store in each region's PostgreSQL. Users
// homed in this region are written here (with an outbox row in the same
// transaction); users homed elsewhere arrive through the replicator.
package users

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"mrnet/api/authv1"
	"mrnet/internal/events"
)

const Schema = `
CREATE TABLE IF NOT EXISTS users (
  user_id             uuid PRIMARY KEY,
  email_norm          text NOT NULL,
  password_hash       text NOT NULL,
  credential_version  bigint NOT NULL DEFAULT 1,
  status              text NOT NULL DEFAULT 'active',
  home_region         text NOT NULL,
  display_name        text NOT NULL DEFAULT '',
  password_changed_at timestamptz NOT NULL,
  created_at          timestamptz NOT NULL,
  updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_norm ON users (email_norm);

CREATE TABLE IF NOT EXISTS outbox (
  id         bigserial PRIMARY KEY,
  topic      text NOT NULL,
  key        text NOT NULL,
  payload    jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at    timestamptz
);
CREATE INDEX IF NOT EXISTS outbox_unsent ON outbox (id) WHERE sent_at IS NULL;

CREATE TABLE IF NOT EXISTS signing_keys (
  kid          text PRIMARY KEY,
  region       text NOT NULL,
  created_at   timestamptz NOT NULL,
  wrapped_seed bytea NOT NULL,
  public_key   bytea NOT NULL
);
`

type User = events.Credential

var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email taken")
)

const cols = `user_id::text, email_norm, password_hash, credential_version, status, home_region, display_name, password_changed_at, created_at`

func scan(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.UserID, &u.EmailNorm, &u.PasswordHash, &u.CredentialVersion, &u.Status,
		&u.HomeRegion, &u.DisplayName, &u.PasswordChangedAt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func ByEmail(ctx context.Context, q Querier, emailNorm string) (*User, error) {
	return scan(q.QueryRow(ctx, `SELECT `+cols+` FROM users WHERE email_norm=$1`, emailNorm))
}

func ByID(ctx context.Context, q Querier, userID string) (*User, error) {
	return scan(q.QueryRow(ctx, `SELECT `+cols+` FROM users WHERE user_id=$1`, userID))
}

func addOutbox(ctx context.Context, tx pgx.Tx, u *User) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox (topic, key, payload) VALUES ($1,$2,$3)`, events.TopicCredentials, u.UserID, b)
	return err
}

// Insert creates a user homed in this region.
func Insert(ctx context.Context, db *pgxpool.Pool, u *User) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (user_id, email_norm, password_hash, credential_version, status, home_region, display_name, password_changed_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			u.UserID, u.EmailNorm, u.PasswordHash, u.CredentialVersion, u.Status, u.HomeRegion, u.DisplayName, u.PasswordChangedAt, u.CreatedAt)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrEmailTaken
		}
		if err != nil {
			return err
		}
		return addOutbox(ctx, tx, u)
	})
}

// ChangePassword sets a new hash and bumps credential_version, if the stored
// version still equals expectVersion (so two concurrent changes cannot both win).
func ChangePassword(ctx context.Context, db *pgxpool.Pool, userID, newHash string, expectVersion int64) (*User, error) {
	var out *User
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		u, err := scan(tx.QueryRow(ctx, `UPDATE users SET password_hash=$2, credential_version=credential_version+1,
			password_changed_at=now(), updated_at=now()
			WHERE user_id=$1 AND credential_version=$3 RETURNING `+cols, userID, newHash, expectVersion))
		if err != nil {
			return err
		}
		out = u
		return addOutbox(ctx, tx, u)
	})
	return out, err
}

// ApplyReplica upserts a user copied from its home region. Older versions are ignored,
// so redelivered or out-of-order events are harmless.
func ApplyReplica(ctx context.Context, db *pgxpool.Pool, u *User) error {
	_, err := db.Exec(ctx, `INSERT INTO users (user_id, email_norm, password_hash, credential_version, status, home_region, display_name, password_changed_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (user_id) DO UPDATE SET email_norm=EXCLUDED.email_norm, password_hash=EXCLUDED.password_hash,
		  credential_version=EXCLUDED.credential_version, status=EXCLUDED.status, home_region=EXCLUDED.home_region,
		  display_name=EXCLUDED.display_name, password_changed_at=EXCLUDED.password_changed_at, updated_at=now()
		WHERE users.credential_version < EXCLUDED.credential_version`,
		u.UserID, u.EmailNorm, u.PasswordHash, u.CredentialVersion, u.Status, u.HomeRegion, u.DisplayName, u.PasswordChangedAt, u.CreatedAt)
	return err
}

// RelayOutbox publishes unsent outbox rows in order and marks them sent.
// This stands in for Debezium change capture: same effect, one process fewer.
func RelayOutbox(ctx context.Context, db *pgxpool.Pool, p *events.Producer) (int, error) {
	n := 0
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, topic, key, payload FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT 200 FOR UPDATE SKIP LOCKED`)
		if err != nil {
			return err
		}
		type row struct {
			id         int64
			topic, key string
			payload    json.RawMessage
		}
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.topic, &r.key, &r.payload); err != nil {
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range batch {
			if err := p.Publish(ctx, r.topic, r.key, r.payload); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE outbox SET sent_at=now() WHERE id=$1`, r.id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RunOutbox polls the outbox until ctx is done.
func RunOutbox(ctx context.Context, db *pgxpool.Pool, p *events.Producer, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := RelayOutbox(ctx, db, p); err != nil {
				onErr(err)
			}
		}
	}
}

// ToProto / FromProto convert for the internal gRPC API.
func ToProto(u *User) *authv1.User {
	return &authv1.User{
		UserId: u.UserID, EmailNorm: u.EmailNorm, PasswordHash: u.PasswordHash,
		CredentialVersion: u.CredentialVersion, Status: u.Status, HomeRegion: u.HomeRegion,
		DisplayName: u.DisplayName, PasswordChangedAtMs: u.PasswordChangedAt.UnixMilli(), CreatedAtMs: u.CreatedAt.UnixMilli(),
	}
}

func FromProto(p *authv1.User) *User {
	return &User{
		UserID: p.UserId, EmailNorm: p.EmailNorm, PasswordHash: p.PasswordHash,
		CredentialVersion: p.CredentialVersion, Status: p.Status, HomeRegion: p.HomeRegion,
		DisplayName: p.DisplayName, PasswordChangedAt: time.UnixMilli(p.PasswordChangedAtMs).UTC(), CreatedAt: time.UnixMilli(p.CreatedAtMs).UTC(),
	}
}
