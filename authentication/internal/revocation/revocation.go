// Package revocation tracks access tokens that must stop working before they
// expire. Revocations are written to Redis (rv:s:<sid>, rv:u:<uid>) so a
// restarting validator can load a snapshot, and published on Kafka so every
// validator in every region learns about them within about a second.
package revocation

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"mrnet/authentication/internal/events"
	"mrnet/authentication/internal/tokens"
)

func sessKey(sid string) string { return "rv:s:" + sid }
func userKey(uid string) string { return "rv:u:" + uid }

// Keep is how long a revocation must be remembered: until any access token
// it covers would have expired anyway.
func Keep(accessTTL time.Duration) time.Duration {
	return accessTTL + tokens.ClockSkew + 30*time.Second
}

var setMaxScript = redis.NewScript(`
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if tonumber(ARGV[1]) > cur then redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2]) end
return 1
`)

// Store writes and reads revocations in a region's Redis.
type Store struct {
	R    redis.UniversalClient
	Keep time.Duration
}

func (s *Store) Apply(ctx context.Context, ev events.Revocation) error {
	switch ev.Kind {
	case events.RevokeSession:
		return s.R.Set(ctx, sessKey(ev.SessionID), ev.At, s.Keep).Err()
	case events.RevokeUser:
		return setMaxScript.Run(ctx, s.R, []string{userKey(ev.UserID)}, ev.RevokedBefore, int64(s.Keep.Seconds())).Err()
	}
	return nil
}

// IsRevoked is the Redis-backed check used by low-volume internal callers
// (account and token services). The validator fleet uses List instead.
func (s *Store) IsRevoked(ctx context.Context, c *tokens.Claims) (bool, error) {
	pipe := s.R.Pipeline()
	sc := pipe.Exists(ctx, sessKey(c.SID))
	uc := pipe.Get(ctx, userKey(c.Subject))
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return false, err
	}
	if sc.Val() > 0 {
		return true, nil
	}
	if v, err := uc.Int64(); err == nil && c.IssuedAt != nil && c.IssuedAt.Unix() < v/1000 {
		return true, nil
	}
	return false, nil
}

// Snapshot scans every master for revocation keys.
func (s *Store) Snapshot(ctx context.Context, l *List) error {
	scan := func(ctx context.Context, c *redis.Client) error {
		it := c.Scan(ctx, 0, "rv:*", 1000).Iterator()
		for it.Next(ctx) {
			k := it.Val()
			v, err := c.Get(ctx, k).Int64()
			if err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(k, "rv:s:"):
				l.Apply(events.Revocation{Kind: events.RevokeSession, SessionID: k[5:], At: v})
			case strings.HasPrefix(k, "rv:u:"):
				l.Apply(events.Revocation{Kind: events.RevokeUser, UserID: k[5:], RevokedBefore: v})
			}
		}
		return it.Err()
	}
	if cc, ok := s.R.(*redis.ClusterClient); ok {
		return cc.ForEachMaster(ctx, scan)
	}
	return scan(ctx, s.R.(*redis.Client))
}

// List is the validator's in-memory revocation list. Entries expire after Keep.
type List struct {
	Keep time.Duration

	mu       sync.RWMutex
	sessions map[string]int64 // sid -> forget after (unix ms)
	users    map[string]userEntry
}

type userEntry struct {
	beforeSec int64
	forget    int64
}

func NewList(keep time.Duration) *List {
	return &List{Keep: keep, sessions: map[string]int64{}, users: map[string]userEntry{}}
}

func (l *List) Apply(ev events.Revocation) {
	forget := time.Now().Add(l.Keep).UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	switch ev.Kind {
	case events.RevokeSession:
		l.sessions[ev.SessionID] = forget
	case events.RevokeUser:
		before := ev.RevokedBefore / 1000
		if cur, ok := l.users[ev.UserID]; !ok || before > cur.beforeSec {
			l.users[ev.UserID] = userEntry{beforeSec: before, forget: forget}
		}
	}
}

func (l *List) IsRevoked(c *tokens.Claims) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if _, ok := l.sessions[c.SID]; ok {
		return true
	}
	if u, ok := l.users[c.Subject]; ok && c.IssuedAt != nil && c.IssuedAt.Unix() < u.beforeSec {
		return true
	}
	return false
}

func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.sessions) + len(l.users)
}

// Sweep drops entries whose tokens have all expired.
func (l *List) Sweep() {
	now := time.Now().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, f := range l.sessions {
		if f < now {
			delete(l.sessions, k)
		}
	}
	for k, u := range l.users {
		if u.forget < now {
			delete(l.users, k)
		}
	}
}
