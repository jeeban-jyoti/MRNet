// Package authcore is the session logic shared by the token and account
// services: start a session, mint a token pair, and revoke.
package authcore

import (
	"context"
	"time"

	"mrnet/authentication/internal/events"
	"mrnet/authentication/internal/revocation"
	"mrnet/authentication/internal/sessions"
	"mrnet/authentication/internal/tokens"
)

type Core struct {
	Region      string
	Issuer      *tokens.Issuer
	Sessions    *sessions.Store
	Revocations *revocation.Store
	Producer    *events.Producer
	RotationKey []byte
}

// NewSession creates a session in this region and returns its token pair.
func (c *Core) NewSession(ctx context.Context, userID, deviceID, scope string, cv int64) (tokens.Pair, string, error) {
	now := time.Now()
	sid := tokens.NewSessionID()
	secret := tokens.NewSecret()
	err := c.Sessions.Create(ctx, sessions.Session{
		UserID: userID, SessionID: sid, RTHash: tokens.HashSecret(secret), RotatedAt: now.UnixMilli(),
		DeviceID: deviceID, Scope: scope, CV: cv,
		CreatedAt: now.UnixMilli(), AbsoluteExp: now.Add(tokens.RefreshAbsolute).UnixMilli(),
	})
	if err != nil {
		return tokens.Pair{}, "", err
	}
	p, err := c.Pair(userID, sid, scope, cv, secret)
	return p, sid, err
}

// Pair signs an access token and formats the refresh token for a session held here.
func (c *Core) Pair(userID, sid, scope string, cv int64, secret []byte) (tokens.Pair, error) {
	at, exp, err := c.Issuer.Issue(userID, sid, scope, cv)
	if err != nil {
		return tokens.Pair{}, err
	}
	rt := tokens.Refresh{Region: c.Region, UserID: userID, SessionID: sid, Secret: secret}
	return tokens.Pair{
		AccessToken:      at,
		AccessExpiresIn:  int64(time.Until(exp).Round(time.Second).Seconds()),
		RefreshToken:     rt.String(),
		RefreshExpiresIn: int64(c.Sessions.TTL.Seconds()),
	}, nil
}

// RevokeSession makes the session's access tokens stop working everywhere.
func (c *Core) RevokeSession(ctx context.Context, userID, sid string) error {
	ev := events.Revocation{Kind: events.RevokeSession, UserID: userID, SessionID: sid, At: time.Now().UnixMilli()}
	if err := c.Revocations.Apply(ctx, ev); err != nil {
		return err
	}
	return c.Producer.Publish(ctx, events.TopicRevocations, userID, ev)
}

// RevokeUserLocal deletes this region's sessions of the user created before
// beforeMs and blocks access tokens issued before it, in this region only.
func (c *Core) RevokeUserLocal(ctx context.Context, userID string, beforeMs int64) error {
	if _, err := c.Sessions.RevokeBefore(ctx, userID, beforeMs); err != nil {
		return err
	}
	return c.Revocations.Apply(ctx, events.Revocation{Kind: events.RevokeUser, UserID: userID, RevokedBefore: beforeMs, At: beforeMs})
}

// RevokeUser does RevokeUserLocal and tells every other region to do the same.
func (c *Core) RevokeUser(ctx context.Context, userID string, beforeMs int64) error {
	if err := c.RevokeUserLocal(ctx, userID, beforeMs); err != nil {
		return err
	}
	return c.Producer.Publish(ctx, events.TopicRevocations, userID,
		events.Revocation{Kind: events.RevokeUser, UserID: userID, RevokedBefore: beforeMs, At: time.Now().UnixMilli()})
}
