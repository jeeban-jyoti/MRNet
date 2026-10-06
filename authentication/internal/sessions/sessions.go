// Package sessions stores refresh-token sessions in Redis Cluster. Every
// state change is one Lua script on the user's shard: the {user_id} hash tag
// keeps a user's sessions and their index set on the same slot.
package sessions

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Session struct {
	UserID      string
	SessionID   string
	RTHash      string
	RTPrevHash  string
	RotatedAt   int64 // unix ms
	DeviceID    string
	Scope       string
	CV          int64
	CreatedAt   int64 // unix ms
	AbsoluteExp int64 // unix ms
}

type Store struct {
	R          redis.UniversalClient
	TTL        time.Duration // sliding lifetime
	RetryGrace time.Duration
}

func sessKey(uid, sid string) string { return "s:{" + uid + "}:" + sid }
func setKey(uid string) string       { return "u:{" + uid + "}:sessions" }

var createScript = redis.NewScript(`
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('EXPIRE', KEYS[1], ARGV[2])
redis.call('SADD', KEYS[2], ARGV[1])
if redis.call('TTL', KEYS[2]) < tonumber(ARGV[2]) then
  redis.call('EXPIRE', KEYS[2], ARGV[2])
end
return 1
`)

// Create stores a new session (or one moved in from another region).
func (s *Store) Create(ctx context.Context, x Session) error {
	ttl := s.ttlFor(x.AbsoluteExp, time.Now().UnixMilli())
	if ttl <= 0 {
		return errors.New("session past absolute expiry")
	}
	return createScript.Run(ctx, s.R, []string{sessKey(x.UserID, x.SessionID), setKey(x.UserID)},
		x.SessionID, ttl,
		"rt_hash", x.RTHash, "rt_prev_hash", x.RTPrevHash, "rotated_at", x.RotatedAt,
		"device_id", x.DeviceID, "scope", x.Scope, "cv", x.CV,
		"created_at", x.CreatedAt, "absolute_exp", x.AbsoluteExp,
	).Err()
}

func (s *Store) ttlFor(absExp, nowMs int64) int64 {
	ttl := int64(s.TTL.Seconds())
	if left := (absExp - nowMs + 999) / 1000; left < ttl {
		ttl = left
	}
	return ttl
}

// Outcome of a rotate or take.
type Outcome string

const (
	OK      Outcome = "ok"      // presented secret was current; rotated
	Retry   Outcome = "retry"   // presented secret was the previous one, within grace: same new secret
	Reused  Outcome = "reused"  // presented secret is stale: session deleted
	Missing Outcome = "missing" // no such session (expired, signed out, or moved)
	Expired Outcome = "expired" // past absolute lifetime: session deleted
)

var rotateScript = redis.NewScript(`
local h = redis.call('HGETALL', KEYS[1])
if #h == 0 then return {'missing'} end
local s = {}
for i = 1, #h, 2 do s[h[i]] = h[i+1] end
local now = tonumber(ARGV[3])
local absexp = tonumber(s['absolute_exp'])
local function fields(tag)
  return {tag, s['device_id'], s['scope'], s['cv'], s['created_at'], s['absolute_exp']}
end
if now >= absexp then
  redis.call('DEL', KEYS[1]); redis.call('SREM', KEYS[2], ARGV[6])
  return {'expired'}
end
if s['rt_hash'] == ARGV[1] then
  redis.call('HSET', KEYS[1], 'rt_prev_hash', s['rt_hash'], 'rt_hash', ARGV[2], 'rotated_at', ARGV[3])
  local ttl = tonumber(ARGV[5])
  local left = math.ceil((absexp - now) / 1000)
  if left < ttl then ttl = left end
  redis.call('EXPIRE', KEYS[1], ttl)
  if redis.call('TTL', KEYS[2]) < ttl then redis.call('EXPIRE', KEYS[2], ttl) end
  return fields('ok')
end
if s['rt_prev_hash'] == ARGV[1] and s['rt_hash'] == ARGV[2]
   and now - tonumber(s['rotated_at']) <= tonumber(ARGV[4]) then
  return fields('retry')
end
redis.call('DEL', KEYS[1]); redis.call('SREM', KEYS[2], ARGV[6])
return {'reused'}
`)

// Rotate implements renew: compare the presented secret hash and swap in newHash.
func (s *Store) Rotate(ctx context.Context, uid, sid, presented, newHash string) (Outcome, *Session, error) {
	now := time.Now().UnixMilli()
	res, err := rotateScript.Run(ctx, s.R, []string{sessKey(uid, sid), setKey(uid)},
		presented, newHash, now, s.RetryGrace.Milliseconds(), int64(s.TTL.Seconds()), sid).StringSlice()
	if err != nil {
		return "", nil, err
	}
	out := Outcome(res[0])
	if out != OK && out != Retry {
		return out, nil, nil
	}
	x := &Session{UserID: uid, SessionID: sid, RTHash: newHash, RTPrevHash: presented, RotatedAt: now, DeviceID: res[1], Scope: res[2]}
	x.CV, _ = strconv.ParseInt(res[3], 10, 64)
	x.CreatedAt, _ = strconv.ParseInt(res[4], 10, 64)
	x.AbsoluteExp, _ = strconv.ParseInt(res[5], 10, 64)
	return out, x, nil
}

var takeScript = redis.NewScript(`
local h = redis.call('HGETALL', KEYS[1])
if #h == 0 then return {'missing'} end
local s = {}
for i = 1, #h, 2 do s[h[i]] = h[i+1] end
redis.call('DEL', KEYS[1]); redis.call('SREM', KEYS[2], ARGV[2])
if s['rt_hash'] ~= ARGV[1] then return {'reused'} end
if tonumber(ARGV[3]) >= tonumber(s['absolute_exp']) then return {'expired'} end
return {'ok', s['device_id'], s['scope'], s['cv'], s['created_at'], s['absolute_exp']}
`)

// Take checks the secret, deletes the session and returns it in one step.
// Another region calls this to move a session to itself. A wrong secret is
// treated like reuse: the session is deleted.
func (s *Store) Take(ctx context.Context, uid, sid, presented string) (Outcome, *Session, error) {
	now := time.Now().UnixMilli()
	res, err := takeScript.Run(ctx, s.R, []string{sessKey(uid, sid), setKey(uid)}, presented, sid, now).StringSlice()
	if err != nil {
		return "", nil, err
	}
	out := Outcome(res[0])
	if out != OK {
		return out, nil, nil
	}
	x := &Session{UserID: uid, SessionID: sid, RTHash: presented, DeviceID: res[1], Scope: res[2]}
	x.CV, _ = strconv.ParseInt(res[3], 10, 64)
	x.CreatedAt, _ = strconv.ParseInt(res[4], 10, 64)
	x.AbsoluteExp, _ = strconv.ParseInt(res[5], 10, 64)
	return out, x, nil
}

var deleteIfMatchScript = redis.NewScript(`
local cur = redis.call('HMGET', KEYS[1], 'rt_hash', 'rt_prev_hash')
if not cur[1] then return 0 end
if cur[1] == ARGV[1] or cur[2] == ARGV[1] then
  redis.call('DEL', KEYS[1]); redis.call('SREM', KEYS[2], ARGV[2])
  return 1
end
return 0
`)

// DeleteIfMatch signs one session out if the secret hash is its current or previous one.
func (s *Store) DeleteIfMatch(ctx context.Context, uid, sid, presented string) (bool, error) {
	n, err := deleteIfMatchScript.Run(ctx, s.R, []string{sessKey(uid, sid), setKey(uid)}, presented, sid).Int()
	return n == 1, err
}

var revokeBeforeScript = redis.NewScript(`
local prefix = ARGV[1]
local before = tonumber(ARGV[2])
local deleted = {}
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local k = prefix .. sid
  local created = redis.call('HGET', k, 'created_at')
  if not created then
    redis.call('SREM', KEYS[1], sid)
  elseif tonumber(created) < before then
    redis.call('DEL', k)
    redis.call('SREM', KEYS[1], sid)
    table.insert(deleted, sid)
  end
end
return deleted
`)

// RevokeBefore deletes every session of the user created before the given
// unix-ms time, atomically, and returns their ids. Sessions created after it
// (such as the one password_change hands back) survive.
func (s *Store) RevokeBefore(ctx context.Context, uid string, beforeMs int64) ([]string, error) {
	return revokeBeforeScript.Run(ctx, s.R, []string{setKey(uid)}, "s:{"+uid+"}:", beforeMs).StringSlice()
}

// Count returns how many live sessions the user has in this region.
func (s *Store) Count(ctx context.Context, uid string) (int64, error) {
	return s.R.SCard(ctx, setKey(uid)).Result()
}

// Get reads a session without changing it.
func (s *Store) Get(ctx context.Context, uid, sid string) (*Session, error) {
	m, err := s.R.HGetAll(ctx, sessKey(uid, sid)).Result()
	if err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, nil
	}
	x := &Session{UserID: uid, SessionID: sid, RTHash: m["rt_hash"], RTPrevHash: m["rt_prev_hash"], DeviceID: m["device_id"], Scope: m["scope"]}
	x.CV, _ = strconv.ParseInt(m["cv"], 10, 64)
	x.RotatedAt, _ = strconv.ParseInt(m["rotated_at"], 10, 64)
	x.CreatedAt, _ = strconv.ParseInt(m["created_at"], 10, 64)
	x.AbsoluteExp, _ = strconv.ParseInt(m["absolute_exp"], 10, 64)
	return x, nil
}
