// Package validator serves validate_access_token from memory only: a
// signature check against the cached JWKS of every region, then a lookup in
// an in-memory revocation list fed by Kafka.
package validator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/events"
	"mrnet/authentication/internal/httpx"
	"mrnet/authentication/internal/infra"
	"mrnet/authentication/internal/revocation"
	"mrnet/authentication/internal/tokens"
)

type Server struct {
	verifier *tokens.Verifier
	revoked  *revocation.List
	cache    *lru.Cache[[32]byte, *tokens.Claims]
	ready    atomic.Bool
}

func Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	accessTTL := config.Dur("ACCESS_TTL", 10*time.Minute)
	keep := revocation.Keep(accessTTL)

	ks := tokens.NewKeySet(config.List("JWKS_URLS"))
	if err := infra.Retry(ctx, "jwks", 2*time.Minute, func(ctx context.Context) error { return ks.Start(ctx, time.Minute) }); err != nil {
		return err
	}
	cache, _ := lru.New[[32]byte, *tokens.Claims](config.Int("VALIDATOR_CACHE_SIZE", 200_000))
	s := &Server{
		verifier: tokens.NewVerifier(ks, config.List("REGIONS")),
		revoked:  revocation.NewList(keep),
		cache:    cache,
	}

	mux := http.NewServeMux()
	httpx.Health(mux, s.ready.Load)
	mux.HandleFunc("POST /v1/token/validate", s.validate)
	srv := &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: httpx.Logged("validator", mux)}

	go func() {
		if err := s.loadRevocations(ctx, keep); err != nil {
			slog.Error("revocation feed stopped", "err", err)
			cancel()
		}
	}()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.revoked.Sweep()
			}
		}
	}()
	return httpx.Serve(ctx, srv, "", "")
}

// loadRevocations loads the Redis snapshot, then replays Kafka from a little
// before the snapshot and reports ready once it has caught up to the end
// offsets it saw at startup. It then keeps consuming forever.
func (s *Server) loadRevocations(ctx context.Context, keep time.Duration) error {
	rdb, err := infra.RedisCluster(ctx, config.List("REDIS_CLUSTER_ADDRS"))
	if err != nil {
		return err
	}
	snapAt := time.Now()
	if err := (&revocation.Store{R: rdb, Keep: keep}).Snapshot(ctx, s.revoked); err != nil {
		return err
	}
	_ = rdb.Close()
	slog.Info("revocation snapshot loaded", "entries", s.revoked.Len())

	brokers := config.List("KAFKA_BROKERS")
	from := snapAt.Add(-10 * time.Second).UnixMilli()
	cl, err := events.NewClient(brokers,
		kgo.ConsumeTopics(events.TopicRevocations),
		kgo.ConsumeResetOffset(kgo.NewOffset().AfterMilli(from)),
	)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := infra.Retry(ctx, "kafka topics", 2*time.Minute, func(ctx context.Context) error { return events.EnsureTopics(ctx, cl) }); err != nil {
		return err
	}
	adm := kadm.NewClient(cl)
	var start, end kadm.ListedOffsets
	if err := infra.Retry(ctx, "kafka offsets", time.Minute, func(ctx context.Context) error {
		var err error
		if start, err = adm.ListOffsetsAfterMilli(ctx, from, events.TopicRevocations); err != nil {
			return err
		}
		end, err = adm.ListEndOffsets(ctx, events.TopicRevocations)
		return err
	}); err != nil {
		return err
	}
	pending := map[int32]int64{} // partition -> end offset still to reach
	end.Each(func(o kadm.ListedOffset) {
		if st, ok := start.Lookup(o.Topic, o.Partition); !ok || st.Offset < o.Offset {
			pending[o.Partition] = o.Offset
		}
	})
	if len(pending) == 0 {
		s.markReady()
	}
	for {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			return nil
		}
		fs.EachError(func(t string, p int32, err error) { slog.Warn("kafka fetch", "partition", p, "err", err) })
		fs.EachRecord(func(rec *kgo.Record) {
			var ev events.Revocation
			if err := json.Unmarshal(rec.Value, &ev); err != nil {
				return
			}
			s.revoked.Apply(ev)
			if want, ok := pending[rec.Partition]; ok && rec.Offset+1 >= want {
				delete(pending, rec.Partition)
				if len(pending) == 0 {
					s.markReady()
				}
			}
		})
	}
}

func (s *Server) markReady() {
	if !s.ready.Swap(true) {
		slog.Info("validator ready", "revocations", s.revoked.Len())
	}
}

type validateReq struct {
	AccessToken   string `json:"access_token"`
	RequiredScope string `json:"required_scope,omitempty"`
}

type validateResp struct {
	Sub   string `json:"sub"`
	Sid   string `json:"sid"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	Iss   string `json:"iss"`
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var req validateReq
	if err := httpx.Decode(r, &req); err != nil || req.AccessToken == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "access_token is required")
		return
	}
	c, err := s.check(req.AccessToken)
	if err != nil {
		reason := "invalid"
		if errors.Is(err, tokens.ErrExpired) {
			reason = "expired"
		} else if errors.Is(err, errRevoked) {
			reason = "revoked"
		}
		httpx.Error(w, http.StatusUnauthorized, reason, "")
		return
	}
	if !tokens.HasScope(c.Scope, req.RequiredScope) {
		httpx.Error(w, http.StatusForbidden, "insufficient_scope", "")
		return
	}
	httpx.JSON(w, http.StatusOK, validateResp{Sub: c.Subject, Sid: c.SID, Scope: c.Scope, Exp: c.ExpiresAt.Unix(), Iss: c.Issuer})
}

var errRevoked = errors.New("revoked")

// check verifies a token, using the LRU so a token presented many times in
// its life is signature-checked once per node. Expiry and revocation are
// checked on every call.
func (s *Server) check(tok string) (*tokens.Claims, error) {
	key := sha256.Sum256([]byte(tok))
	c, ok := s.cache.Get(key)
	if ok {
		if time.Now().After(c.ExpiresAt.Add(tokens.ClockSkew)) {
			s.cache.Remove(key)
			return nil, tokens.ErrExpired
		}
	} else {
		var err error
		if c, err = s.verifier.Verify(tok); err != nil {
			return nil, err
		}
		s.cache.Add(key, c)
	}
	if s.revoked.IsRevoked(c) {
		return nil, errRevoked
	}
	return c, nil
}
