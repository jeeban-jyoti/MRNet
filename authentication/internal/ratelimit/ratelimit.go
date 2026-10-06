// Package ratelimit keeps counters in the region's rate-limit Redis
// (no persistence: losing it only resets the counters).
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limiter struct{ R redis.UniversalClient }

var windowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return n
`)

// Allow counts one hit in the current 1-minute window and reports whether
// the key is still under limit, plus how long until the window resets.
// If Redis is down it fails open: rate limits must not take auth down.
func (l *Limiter) Allow(ctx context.Context, key string, limit int) (bool, time.Duration) {
	now := time.Now()
	win := now.Unix() / 60
	k := key + ":" + strconv.FormatInt(win, 10)
	n, err := windowScript.Run(ctx, l.R, []string{k}, 70).Int()
	if err != nil {
		return true, 0
	}
	if n > limit {
		return false, time.Duration(60-now.Unix()%60) * time.Second
	}
	return true, 0
}

// Account failure tracking: after FreeFailures wrong passwords the account is
// slowed down with a growing delay (2s, 4s, 8s ... capped at MaxDelay). There
// is never a hard lockout, so an attacker cannot lock a real user out.
const (
	FreeFailures = 5
	MaxDelay     = 5 * time.Minute
	failWindow   = 15 * time.Minute
)

func EmailKey(emailNorm string) string {
	h := sha256.Sum256([]byte(emailNorm))
	return "rl:acct:" + hex.EncodeToString(h[:12])
}

// AccountDelay returns how long the caller must wait before trying this account again.
func (l *Limiter) AccountDelay(ctx context.Context, acctKey string) time.Duration {
	ttl, err := l.R.PTTL(ctx, acctKey+":wait").Result()
	if err != nil || ttl <= 0 {
		return 0
	}
	return ttl
}

var failScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
local free = tonumber(ARGV[2])
if n > free then
  local d = math.min(2 ^ (n - free), tonumber(ARGV[3]))
  redis.call('SET', KEYS[2], '1', 'EX', d)
end
return n
`)

func (l *Limiter) AccountFailed(ctx context.Context, acctKey string) {
	_ = failScript.Run(ctx, l.R, []string{acctKey + ":fails", acctKey + ":wait"},
		int(failWindow.Seconds()), FreeFailures, int(MaxDelay.Seconds())).Err()
}

func (l *Limiter) AccountSucceeded(ctx context.Context, acctKey string) {
	_ = l.R.Del(ctx, acctKey+":fails", acctKey+":wait").Err()
}
