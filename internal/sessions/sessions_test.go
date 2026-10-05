package sessions

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	mr := miniredis.RunT(t)
	return &Store{R: redis.NewClient(&redis.Options{Addr: mr.Addr()}), TTL: 30 * 24 * time.Hour, RetryGrace: 10 * time.Second}, mr
}

func create(t *testing.T, s *Store, uid, sid, hash string) {
	now := time.Now()
	err := s.Create(t.Context(), Session{UserID: uid, SessionID: sid, RTHash: hash, RotatedAt: now.UnixMilli(),
		DeviceID: "headset-1", Scope: "mr.world", CV: 1, CreatedAt: now.UnixMilli(), AbsoluteExp: now.Add(90 * 24 * time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRotateRetryReuse(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	create(t, s, "u1", "s1", "h0")

	out, sess, err := s.Rotate(ctx, "u1", "s1", "h0", "h1")
	if err != nil || out != OK || sess.DeviceID != "headset-1" || sess.CV != 1 {
		t.Fatalf("first rotate: %v %v %+v", out, err, sess)
	}
	// Client retry with the old secret inside the grace window: same new secret.
	if out, _, _ := s.Rotate(ctx, "u1", "s1", "h0", "h1"); out != Retry {
		t.Fatalf("retry: %v", out)
	}
	// Normal next rotation.
	if out, _, _ := s.Rotate(ctx, "u1", "s1", "h1", "h2"); out != OK {
		t.Fatalf("second rotate: %v", out)
	}
	// Replaying h0 now is theft: the session dies.
	if out, _, _ := s.Rotate(ctx, "u1", "s1", "h0", "hx"); out != Reused {
		t.Fatalf("reuse: %v", out)
	}
	if out, _, _ := s.Rotate(ctx, "u1", "s1", "h2", "h3"); out != Missing {
		t.Fatalf("after reuse the session must be gone, got %v", out)
	}
	if n, _ := s.Count(ctx, "u1"); n != 0 {
		t.Fatalf("index set not cleaned: %d", n)
	}
}

func TestRetryGraceExpires(t *testing.T) {
	s, _ := newStore(t)
	s.RetryGrace = 0
	ctx := t.Context()
	create(t, s, "u1", "s1", "h0")
	s.Rotate(ctx, "u1", "s1", "h0", "h1")
	time.Sleep(5 * time.Millisecond)
	if out, _, _ := s.Rotate(ctx, "u1", "s1", "h0", "h1"); out != Reused {
		t.Fatalf("retry after grace must count as reuse, got %v", out)
	}
}

func TestTake(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	create(t, s, "u1", "s1", "h0")
	if out, _, _ := s.Take(ctx, "u1", "s1", "wrong"); out != Reused {
		t.Fatalf("wrong secret: %v", out)
	}
	create(t, s, "u1", "s2", "h0")
	out, sess, _ := s.Take(ctx, "u1", "s2", "h0")
	if out != OK || sess.DeviceID != "headset-1" {
		t.Fatalf("take: %v %+v", out, sess)
	}
	if out, _, _ := s.Take(ctx, "u1", "s2", "h0"); out != Missing {
		t.Fatalf("second take: %v", out)
	}
}

func TestDeleteIfMatchAndRevokeBefore(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	create(t, s, "u1", "s1", "h0")
	if ok, _ := s.DeleteIfMatch(ctx, "u1", "s1", "nope"); ok {
		t.Fatal("deleted with wrong secret")
	}
	if ok, _ := s.DeleteIfMatch(ctx, "u1", "s1", "h0"); !ok {
		t.Fatal("did not delete with right secret")
	}

	create(t, s, "u1", "a", "x")
	create(t, s, "u1", "b", "y")
	cut := time.Now().UnixMilli() + 1
	time.Sleep(5 * time.Millisecond)
	create(t, s, "u1", "c", "z")
	gone, err := s.RevokeBefore(ctx, "u1", cut)
	if err != nil || len(gone) != 2 {
		t.Fatalf("revoke before: %v %v", gone, err)
	}
	if n, _ := s.Count(ctx, "u1"); n != 1 {
		t.Fatalf("expected only the newer session left, have %d", n)
	}
}
