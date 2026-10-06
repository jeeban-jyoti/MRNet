// Package infra opens connections to the stores, retrying while containers start.
package infra

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Retry calls f until it succeeds or the deadline passes.
func Retry(ctx context.Context, what string, max time.Duration, f func(context.Context) error) error {
	deadline := time.Now().Add(max)
	wait := 250 * time.Millisecond
	for {
		err := f(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: %w", what, err)
		}
		slog.Info("waiting for dependency", "what", what, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait < 2*time.Second {
			wait *= 2
		}
	}
}

func Postgres(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return pool, Retry(ctx, "postgres "+cfg.ConnConfig.Host, 90*time.Second, pool.Ping)
}

// RedisCluster connects to the region's session cluster and waits until
// the cluster reports every slot covered.
func RedisCluster(ctx context.Context, addrs []string) (redis.UniversalClient, error) {
	c := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:        addrs,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     64,
	})
	return c, Retry(ctx, "redis cluster", 90*time.Second, func(ctx context.Context) error {
		info, err := c.ClusterInfo(ctx).Result()
		if err != nil {
			return err
		}
		if !strings.Contains(info, "cluster_state:ok") {
			return fmt.Errorf("cluster not ready")
		}
		return c.Ping(ctx).Err()
	})
}

func Redis(ctx context.Context, addr string) (redis.UniversalClient, error) {
	c := redis.NewClient(&redis.Options{Addr: addr, ReadTimeout: 500 * time.Millisecond, WriteTimeout: 500 * time.Millisecond, PoolSize: 64})
	return c, Retry(ctx, "redis "+addr, 90*time.Second, func(ctx context.Context) error { return c.Ping(ctx).Err() })
}
