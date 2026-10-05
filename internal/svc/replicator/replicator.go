// Package replicator copies auth state between regions. For every other
// region it consumes that region's Kafka and applies events that region
// wrote (origin header) to this region:
//
//   - auth.credentials: upsert the user into the local users table, so any
//     region can sign in any user from its own copy.
//   - auth.revocations: write the revocation into local Redis, delete the
//     user's local sessions for user-level revocations, and re-publish into
//     local Kafka so this region's validators hear it.
//   - signout requests aimed at this region: check the secret, sign the
//     session out, and publish the resulting revocation from here.
//
// Filtering on origin means each event crosses each region boundary once,
// even though every region re-publishes what it receives.
package replicator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"mrnet/internal/config"
	"mrnet/internal/events"
	"mrnet/internal/httpx"
	"mrnet/internal/infra"
	"mrnet/internal/revocation"
	"mrnet/internal/sessions"
	"mrnet/internal/tokens"
	"mrnet/internal/users"
)

type Replicator struct {
	Region   string
	DB       *pgxpool.Pool
	Sessions *sessions.Store
	Revs     *revocation.Store
	Local    *events.Producer
}

func Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	region := config.MustStr("REGION")
	accessTTL := config.Dur("ACCESS_TTL", 10*time.Minute)

	db, err := infra.Postgres(ctx, config.MustStr("POSTGRES_PRIMARY_URL"), 10)
	if err != nil {
		return err
	}
	rdb, err := infra.RedisCluster(ctx, config.List("REDIS_CLUSTER_ADDRS"))
	if err != nil {
		return err
	}
	local, err := events.NewClient(config.List("KAFKA_BROKERS"))
	if err != nil {
		return err
	}
	if err := infra.Retry(ctx, "local kafka", 2*time.Minute, func(ctx context.Context) error { return events.EnsureTopics(ctx, local) }); err != nil {
		return err
	}
	r := &Replicator{
		Region:   region,
		DB:       db,
		Sessions: &sessions.Store{R: rdb, TTL: tokens.RefreshTTL, RetryGrace: tokens.RetryGrace},
		Revs:     &revocation.Store{R: rdb, Keep: revocation.Keep(accessTTL)},
		Local:    &events.Producer{Client: local, Region: region},
	}

	remotes := config.Map("REMOTE_KAFKA") // region -> brokers (separated by ';')
	errc := make(chan error, len(remotes))
	for remote, brokers := range remotes {
		go func() { errc <- r.follow(ctx, remote, splitSemi(brokers)) }()
	}

	mux := http.NewServeMux()
	httpx.Health(mux, nil)
	go func() {
		errc <- httpx.Serve(ctx, &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: mux}, "", "")
	}()
	return <-errc
}

// follow consumes one remote region with a consumer group, committing only
// after events are applied (at-least-once; every apply is idempotent).
func (r *Replicator) follow(ctx context.Context, remote string, brokers []string) error {
	cl, err := events.NewClient(brokers,
		kgo.ConsumerGroup("replicator-"+r.Region+"-from-"+remote),
		kgo.ConsumeTopics(events.TopicCredentials, events.TopicRevocations),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := infra.Retry(ctx, "kafka "+remote, 5*time.Minute, func(ctx context.Context) error { return events.EnsureTopics(ctx, cl) }); err != nil {
		return err
	}
	slog.Info("following region", "remote", remote, "brokers", brokers)
	for {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			return nil
		}
		fs.EachError(func(t string, p int32, err error) {
			slog.Warn("remote fetch", "remote", remote, "topic", t, "err", err)
		})
		fs.EachRecord(func(rec *kgo.Record) {
			if events.Origin(rec) != remote {
				return // written by some other region; that region's own follower handles it
			}
			for attempt := 0; ; attempt++ {
				err := r.apply(ctx, rec)
				if err == nil || ctx.Err() != nil {
					return
				}
				slog.Warn("apply failed, retrying", "remote", remote, "topic", rec.Topic, "err", err)
				time.Sleep(min(time.Duration(attempt+1)*200*time.Millisecond, 5*time.Second))
			}
		})
		if err := cl.CommitUncommittedOffsets(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("commit", "remote", remote, "err", err)
		}
	}
}

func (r *Replicator) apply(ctx context.Context, rec *kgo.Record) error {
	switch rec.Topic {
	case events.TopicCredentials:
		var u users.User
		if err := json.Unmarshal(rec.Value, &u); err != nil {
			slog.Error("bad credential event", "err", err)
			return nil
		}
		return users.ApplyReplica(ctx, r.DB, &u)

	case events.TopicRevocations:
		var ev events.Revocation
		if err := json.Unmarshal(rec.Value, &ev); err != nil {
			slog.Error("bad revocation event", "err", err)
			return nil
		}
		switch ev.Kind {
		case events.RevokeSession:
			if err := r.Revs.Apply(ctx, ev); err != nil {
				return err
			}
			return r.Local.PublishRecord(ctx, rec)
		case events.RevokeUser:
			if _, err := r.Sessions.RevokeBefore(ctx, ev.UserID, ev.RevokedBefore); err != nil {
				return err
			}
			if err := r.Revs.Apply(ctx, ev); err != nil {
				return err
			}
			return r.Local.PublishRecord(ctx, rec)
		case events.SignoutRequest:
			if ev.TargetRegion != r.Region {
				return nil
			}
			ok, err := r.Sessions.DeleteIfMatch(ctx, ev.UserID, ev.SessionID, ev.SecretHash)
			if err != nil || !ok {
				return err
			}
			out := events.Revocation{Kind: events.RevokeSession, UserID: ev.UserID, SessionID: ev.SessionID, At: time.Now().UnixMilli()}
			if err := r.Revs.Apply(ctx, out); err != nil {
				return err
			}
			return r.Local.Publish(ctx, events.TopicRevocations, ev.UserID, out)
		}
	}
	return nil
}

func splitSemi(s string) []string {
	var out []string
	for _, b := range strings.Split(s, ";") {
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	return out
}
