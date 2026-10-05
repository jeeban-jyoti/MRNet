// Package keys manages a region's Ed25519 signing keys. Keys are stored in the
// region's PostgreSQL wrapped by KMS, rotated every RotateAfter, and kept in the
// JWKS for one more rotation period so tokens signed just before a rotation
// still validate.
package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"mrnet/internal/kms"
)

type Key struct {
	Kid       string
	Region    string
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	CreatedAt time.Time
}

type Store struct {
	DB          *pgxpool.Pool
	KMS         *kms.KMS
	Region      string
	RotateAfter time.Duration

	mu   sync.RWMutex
	keys []Key // newest first
}

const rotationLock = 7_301_001 // pg advisory lock id for key rotation

// Start loads keys (creating the first one if needed) and checks for rotation every minute.
func (s *Store) Start(ctx context.Context) error {
	if err := s.refresh(ctx); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.refresh(ctx); err != nil {
					slog.Error("signing key refresh", "err", err)
				}
			}
		}
	}()
	return nil
}

func (s *Store) refresh(ctx context.Context) error {
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rotationLock); err != nil {
			return err
		}
		var newest time.Time
		err := tx.QueryRow(ctx, `SELECT created_at FROM signing_keys WHERE region=$1 ORDER BY created_at DESC LIMIT 1`, s.Region).Scan(&newest)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil && time.Since(newest) < s.RotateAfter {
			return nil
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		kid := newKid(s.Region)
		wrapped, err := s.KMS.Wrap(priv.Seed(), []byte(kid))
		if err != nil {
			return err
		}
		slog.Info("created signing key", "kid", kid)
		_, err = tx.Exec(ctx, `INSERT INTO signing_keys (kid, region, created_at, wrapped_seed, public_key) VALUES ($1,$2,now(),$3,$4)`,
			kid, s.Region, wrapped, []byte(pub))
		return err
	})
	if err != nil {
		return fmt.Errorf("ensure signing key: %w", err)
	}

	rows, err := s.DB.Query(ctx, `SELECT kid, created_at, wrapped_seed, public_key FROM signing_keys
		WHERE region=$1 AND created_at > now() - $2::interval ORDER BY created_at DESC`,
		s.Region, fmt.Sprintf("%d seconds", int(2*s.RotateAfter.Seconds())))
	if err != nil {
		return err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		var wrapped, pub []byte
		if err := rows.Scan(&k.Kid, &k.CreatedAt, &wrapped, &pub); err != nil {
			return err
		}
		seed, err := s.KMS.Unwrap(wrapped, []byte(k.Kid))
		if err != nil {
			return fmt.Errorf("unwrap %s: %w", k.Kid, err)
		}
		k.Region = s.Region
		k.Private = ed25519.NewKeyFromSeed(seed)
		k.Public = ed25519.PublicKey(pub)
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	s.mu.Lock()
	s.keys = out
	s.mu.Unlock()
	return nil
}

// Current is the key new tokens are signed with.
func (s *Store) Current() Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[0]
}

// Published is the current and previous key, for the JWKS.
func (s *Store) Published() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Key(nil), s.keys...)
}

func newKid(region string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return region + "-" + time.Now().UTC().Format("20060102") + "-" + hex.EncodeToString(b)
}

// NewStatic returns a store holding one fixed key, for tests and benchmarks.
func NewStatic(region string) *Store {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Store{Region: region, keys: []Key{{Kid: newKid(region), Region: region, Private: priv, Public: pub, CreatedAt: time.Now()}}}
}
