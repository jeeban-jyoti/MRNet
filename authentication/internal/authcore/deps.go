package authcore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"mrnet/authentication/api/authv1"
	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/events"
	"mrnet/authentication/internal/grpcx"
	"mrnet/authentication/internal/hashing"
	"mrnet/authentication/internal/infra"
	"mrnet/authentication/internal/keys"
	"mrnet/authentication/internal/kms"
	"mrnet/authentication/internal/ratelimit"
	"mrnet/authentication/internal/registry"
	"mrnet/authentication/internal/revocation"
	"mrnet/authentication/internal/sessions"
	"mrnet/authentication/internal/tokens"
)

// Deps is everything the token and account services connect to.
type Deps struct {
	Core     *Core
	Primary  *pgxpool.Pool
	Replica  *pgxpool.Pool
	Limiter  *ratelimit.Limiter
	Hasher   *hashing.Client
	Kafka    *kgo.Client
	Verifier *tokens.Verifier
	Registry *registry.Registry

	// Cross-region gRPC clients, by region.
	PeerSessions   map[string]authv1.SessionsClient
	PeerAccounts   map[string]authv1.AccountsClient
	PeerTimeout    time.Duration
	InternalSecret string
}

func Connect(ctx context.Context) (*Deps, error) {
	region := config.MustStr("REGION")
	accessTTL := config.Dur("ACCESS_TTL", 10*time.Minute)
	internal := config.MustStr("INTERNAL_SECRET")
	d := &Deps{
		InternalSecret: internal,
		PeerSessions:   map[string]authv1.SessionsClient{},
		PeerAccounts:   map[string]authv1.AccountsClient{},
		PeerTimeout:    config.Dur("PEER_TIMEOUT", 3*time.Second),
	}
	hasherConn, err := grpcx.Dial(config.MustStr("HASHER_GRPC"), internal)
	if err != nil {
		return nil, err
	}
	d.Hasher = &hashing.Client{C: authv1.NewHasherClient(hasherConn), Timeout: 5 * time.Second}
	for region, target := range config.Map("PEER_TOKEN_GRPC") {
		conn, err := grpcx.Dial(target, internal)
		if err != nil {
			return nil, err
		}
		d.PeerSessions[region] = authv1.NewSessionsClient(conn)
	}
	for region, target := range config.Map("PEER_ACCOUNT_GRPC") {
		conn, err := grpcx.Dial(target, internal)
		if err != nil {
			return nil, err
		}
		d.PeerAccounts[region] = authv1.NewAccountsClient(conn)
	}
	if d.Primary, err = infra.Postgres(ctx, config.MustStr("POSTGRES_PRIMARY_URL"), 20); err != nil {
		return nil, err
	}
	if d.Replica, err = infra.Postgres(ctx, config.Str("POSTGRES_REPLICA_URL", config.MustStr("POSTGRES_PRIMARY_URL")), 40); err != nil {
		return nil, err
	}
	regPool, err := infra.Postgres(ctx, config.MustStr("REGISTRY_URL"), 10)
	if err != nil {
		return nil, err
	}
	d.Registry = &registry.Registry{DB: regPool}

	sessRedis, err := infra.RedisCluster(ctx, config.List("REDIS_CLUSTER_ADDRS"))
	if err != nil {
		return nil, err
	}
	rlRedis, err := infra.Redis(ctx, config.MustStr("REDIS_RL_ADDR"))
	if err != nil {
		return nil, err
	}
	d.Limiter = &ratelimit.Limiter{R: rlRedis}

	if d.Kafka, err = events.NewClient(config.List("KAFKA_BROKERS")); err != nil {
		return nil, err
	}
	if err := infra.Retry(ctx, "kafka", 2*time.Minute, func(ctx context.Context) error { return events.EnsureTopics(ctx, d.Kafka) }); err != nil {
		return nil, err
	}

	k, err := kms.New(config.Key("KMS_MASTER_KEY", 32))
	if err != nil {
		return nil, err
	}
	ks := &keys.Store{DB: d.Primary, KMS: k, Region: region, RotateAfter: config.Dur("KEY_ROTATE_AFTER", 30*24*time.Hour)}
	if err := infra.Retry(ctx, "signing keys", time.Minute, ks.Start); err != nil {
		return nil, err
	}

	jwks := tokens.NewKeySet(config.List("JWKS_URLS"))
	jwks.StartBackground(ctx, time.Minute)
	d.Verifier = tokens.NewVerifier(jwks, config.List("REGIONS"))

	d.Core = &Core{
		Region:      region,
		Issuer:      &tokens.Issuer{Region: region, Keys: ks, TTL: accessTTL},
		Sessions:    &sessions.Store{R: sessRedis, TTL: tokens.RefreshTTL, RetryGrace: tokens.RetryGrace},
		Revocations: &revocation.Store{R: sessRedis, Keep: revocation.Keep(accessTTL)},
		Producer:    &events.Producer{Client: d.Kafka, Region: region},
		RotationKey: config.Key("ROTATION_KEY", 32),
	}
	return d, nil
}

// Authenticate checks a bearer access token with the shared verifier and the
// region's revocation keys in Redis.
func (d *Deps) Authenticate(ctx context.Context, bearer string) (*tokens.Claims, error) {
	if bearer == "" {
		return nil, tokens.ErrInvalid
	}
	c, err := d.Verifier.Verify(bearer)
	if err != nil {
		return nil, err
	}
	revoked, err := d.Core.Revocations.IsRevoked(ctx, c)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrRevoked
	}
	return c, nil
}

var ErrRevoked = errors.New("revoked")
