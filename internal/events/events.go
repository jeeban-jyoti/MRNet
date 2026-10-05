// Package events wraps Kafka: topic names, event shapes and a producer.
// Every record carries an "origin" header naming the region that wrote it,
// which the replicator uses to copy each event across regions exactly once.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	TopicRevocations = "auth.revocations"
	TopicEvents      = "auth.events"
	TopicCredentials = "auth.credentials"
	OriginHeader     = "origin"
)

// Revocation kinds.
const (
	RevokeSession  = "session"         // one session signed out or killed
	RevokeUser     = "user"            // every session of a user created before RevokedBefore
	SignoutRequest = "signout_request" // ask the session's region to verify and sign it out
)

type Revocation struct {
	Kind          string `json:"kind"`
	UserID        string `json:"user_id"`
	SessionID     string `json:"session_id,omitempty"`
	RevokedBefore int64  `json:"revoked_before_ms,omitempty"` // user kind
	SecretHash    string `json:"secret_hash,omitempty"`       // signout_request
	TargetRegion  string `json:"target_region,omitempty"`     // signout_request
	At            int64  `json:"at_ms"`
}

// Credential is a user row as the home region wrote it; other regions upsert it.
type Credential struct {
	UserID            string    `json:"user_id"`
	EmailNorm         string    `json:"email_norm"`
	PasswordHash      string    `json:"password_hash"`
	CredentialVersion int64     `json:"credential_version"`
	Status            string    `json:"status"`
	HomeRegion        string    `json:"home_region"`
	DisplayName       string    `json:"display_name"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// Audit is one entry on the auth.events stream.
type Audit struct {
	Type     string `json:"type"`
	UserID   string `json:"user_id,omitempty"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason,omitempty"`
	IP       string `json:"ip,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Region   string `json:"region"`
	At       int64  `json:"at_ms"`
}

func NewClient(brokers []string, opts ...kgo.Opt) (*kgo.Client, error) {
	base := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ProducerLinger(2 * time.Millisecond),
		kgo.RecordRetries(10),
	}
	return kgo.NewClient(append(base, opts...)...)
}

// EnsureTopics creates the auth topics if they do not exist.
func EnsureTopics(ctx context.Context, cl *kgo.Client) error {
	adm := kadm.NewClient(cl)
	res, err := adm.CreateTopics(ctx, 3, 1, map[string]*string{}, TopicRevocations, TopicEvents, TopicCredentials)
	if err != nil {
		return err
	}
	for _, r := range res {
		if r.Err != nil && !errors.Is(r.Err, kerr.TopicAlreadyExists) {
			return r.Err
		}
	}
	return nil
}

type Producer struct {
	Client *kgo.Client
	Region string
}

func (p *Producer) record(topic, key string, v any) (*kgo.Record, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &kgo.Record{Topic: topic, Key: []byte(key), Value: b,
		Headers: []kgo.RecordHeader{{Key: OriginHeader, Value: []byte(p.Region)}}}, nil
}

// Publish writes synchronously; use it when the caller must know the event is durable.
func (p *Producer) Publish(ctx context.Context, topic, key string, v any) error {
	rec, err := p.record(topic, key, v)
	if err != nil {
		return err
	}
	return p.Client.ProduceSync(ctx, rec).FirstErr()
}

// PublishRecord re-publishes a record as is (headers included), for mirroring.
func (p *Producer) PublishRecord(ctx context.Context, rec *kgo.Record) error {
	out := &kgo.Record{Topic: rec.Topic, Key: rec.Key, Value: rec.Value, Headers: rec.Headers}
	return p.Client.ProduceSync(ctx, out).FirstErr()
}

// Audit writes to the audit stream without waiting.
func (p *Producer) Audit(a Audit) {
	a.Region = p.Region
	a.At = time.Now().UnixMilli()
	rec, err := p.record(TopicEvents, a.UserID, a)
	if err != nil {
		return
	}
	p.Client.Produce(context.Background(), rec, func(_ *kgo.Record, err error) {
		if err != nil {
			slog.Warn("audit publish failed", "err", err)
		}
	})
}

func Origin(rec *kgo.Record) string {
	for _, h := range rec.Headers {
		if h.Key == OriginHeader {
			return string(h.Value)
		}
	}
	return ""
}
