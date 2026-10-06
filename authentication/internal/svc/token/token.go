// Package token is the token service: signin, renew and signout, the JWKS,
// and the internal endpoint other regions call to move a session to themselves.
package token

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mrnet/authentication/api/authv1"
	"mrnet/authentication/internal/authcore"
	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/events"
	"mrnet/authentication/internal/grpcx"
	"mrnet/authentication/internal/hashing"
	"mrnet/authentication/internal/httpx"
	"mrnet/authentication/internal/password"
	"mrnet/authentication/internal/ratelimit"
	"mrnet/authentication/internal/registry"
	"mrnet/authentication/internal/sessions"
	"mrnet/authentication/internal/tokens"
	"mrnet/authentication/internal/users"
)

type Server struct {
	authv1.UnimplementedSessionsServer
	*authcore.Deps
	signinPerIP int
}

func Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d, err := authcore.Connect(ctx)
	if err != nil {
		return err
	}
	s := &Server{Deps: d, signinPerIP: config.Int("SIGNIN_PER_IP_PER_MIN", 120)}

	mux := http.NewServeMux()
	httpx.Health(mux, nil)
	mux.HandleFunc("POST /v1/signin", s.signin)
	mux.HandleFunc("POST /v1/token/renew", s.renew)
	mux.HandleFunc("POST /v1/signout", s.signout)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)

	gs := grpcx.NewServer(d.InternalSecret)
	authv1.RegisterSessionsServer(gs, s)
	errc := make(chan error, 2)
	go func() { errc <- grpcx.Serve(ctx, config.Str("GRPC_ADDR", ":9090"), gs) }()
	go func() {
		errc <- httpx.Serve(ctx, &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: httpx.Logged("token", mux)}, "", "")
	}()
	return <-errc
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=60")
	httpx.JSON(w, http.StatusOK, tokens.ToJWKS(s.Core.Issuer.Keys.Published()))
}

type signinReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

func unauthorized(w http.ResponseWriter, reason string) {
	httpx.Error(w, http.StatusUnauthorized, reason, "")
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds() + 0.999)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "")
}

func (s *Server) signin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req signinReq
	if err := httpx.Decode(r, &req); err != nil || req.Email == "" || req.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "email and password are required")
		return
	}
	ip := httpx.ClientIP(r)
	audit := events.Audit{Type: "signin", IP: ip, DeviceID: req.DeviceID}
	if ok, wait := s.Limiter.Allow(ctx, "rl:ip:signin:"+ip, s.signinPerIP); !ok {
		tooMany(w, wait)
		return
	}
	email, err := password.NormalizeEmail(req.Email)
	if err != nil {
		unauthorized(w, "invalid_credentials")
		return
	}
	acct := ratelimit.EmailKey(email)
	if wait := s.Limiter.AccountDelay(ctx, acct); wait > 0 {
		tooMany(w, wait)
		return
	}

	u, err := s.findUser(ctx, email)
	if err != nil {
		slog.Error("signin lookup", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	hash := ""
	if u != nil {
		hash = u.PasswordHash
	}
	// Unknown emails still cost one hash, so timing does not reveal which emails exist.
	res, err := s.Hasher.Verify(ctx, req.Password, hash)
	if errors.Is(err, hashing.ErrBusy) {
		tooMany(w, time.Second)
		return
	}
	if err != nil {
		slog.Error("signin verify", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	if u == nil || !res.Ok || u.Status != "active" {
		s.Limiter.AccountFailed(ctx, acct)
		audit.Reason = "invalid_credentials"
		if u != nil {
			audit.UserID = u.UserID
		}
		s.Core.Producer.Audit(audit)
		unauthorized(w, "invalid_credentials")
		return
	}
	s.Limiter.AccountSucceeded(ctx, acct)
	pair, _, err := s.Core.NewSession(ctx, u.UserID, req.DeviceID, tokens.DefaultScp, u.CredentialVersion)
	if err != nil {
		slog.Error("signin session", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	audit.UserID, audit.OK = u.UserID, true
	s.Core.Producer.Audit(audit)
	httpx.JSON(w, http.StatusOK, pair)
}

// findUser reads the local replica, then the local primary (covers a signin
// right after a signup here, before the replica catches up), then the home
// region (covers an account seconds old whose credentials have not been
// copied here yet). It returns nil, nil for an unknown email.
func (s *Server) findUser(ctx context.Context, email string) (*users.User, error) {
	u, err := users.ByEmail(ctx, s.Replica, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		slog.Warn("replica read failed, using primary", "err", err)
	}
	u, err = users.ByEmail(ctx, s.Primary, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		return nil, err
	}
	entry, err := s.Registry.Lookup(ctx, email)
	if errors.Is(err, registry.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if entry.HomeRegion == s.Core.Region {
		return nil, nil
	}
	peer, ok := s.PeerAccounts[entry.HomeRegion]
	if !ok {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.PeerTimeout)
	defer cancel()
	pu, err := peer.GetUserByEmail(ctx, &authv1.GetUserByEmailRequest{EmailNorm: email})
	if grpcx.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return users.FromProto(pu), nil
}

type renewReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req renewReq
	if err := httpx.Decode(r, &req); err != nil || req.RefreshToken == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "refresh_token is required")
		return
	}
	rt, err := tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		unauthorized(w, "invalid")
		return
	}
	presented := tokens.HashSecret(rt.Secret)
	next := tokens.NextSecret(s.Core.RotationKey, rt.SessionID, rt.Secret)
	nextHash := tokens.HashSecret(next)

	// The session is normally here. It can also be here under another region's
	// token when this is a client retry of a renew that already moved it.
	out, sess, err := s.Core.Sessions.Rotate(ctx, rt.UserID, rt.SessionID, presented, nextHash)
	if err != nil {
		slog.Error("renew rotate", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	if out == sessions.Missing && rt.Region != s.Core.Region {
		out, sess, err = s.moveHere(ctx, rt, presented, nextHash)
		if err != nil {
			slog.Warn("session move failed", "from", rt.Region, "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "session_region_unavailable", "sign in again")
			return
		}
	}
	audit := events.Audit{Type: "renew", UserID: rt.UserID, IP: httpx.ClientIP(r)}
	switch out {
	case sessions.OK, sessions.Retry:
	case sessions.Reused:
		// A stale secret means the token was copied: kill the session everywhere.
		if err := s.Core.RevokeSession(ctx, rt.UserID, rt.SessionID); err != nil {
			slog.Error("revoke reused session", "err", err)
		}
		audit.Reason = "reused"
		s.Core.Producer.Audit(audit)
		unauthorized(w, "reused")
		return
	case sessions.Expired:
		unauthorized(w, "expired")
		return
	default:
		unauthorized(w, "revoked")
		return
	}
	pair, err := s.Core.Pair(rt.UserID, rt.SessionID, sess.Scope, sess.CV, next)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal", "")
		return
	}
	audit.OK, audit.DeviceID = true, sess.DeviceID
	if out == sessions.Retry {
		audit.Reason = "retry"
	}
	s.Core.Producer.Audit(audit)
	httpx.JSON(w, http.StatusOK, pair)
}

// moveHere asks the session's region to hand the session over, then stores it
// here already rotated, so the returned refresh token names this region.
func (s *Server) moveHere(ctx context.Context, rt tokens.Refresh, presented, nextHash string) (sessions.Outcome, *sessions.Session, error) {
	peer, ok := s.PeerSessions[rt.Region]
	if !ok {
		return sessions.Missing, nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.PeerTimeout)
	defer cancel()
	resp, err := peer.TakeSession(ctx, &authv1.TakeSessionRequest{UserId: rt.UserID, SessionId: rt.SessionID, SecretHash: presented})
	if err != nil {
		return "", nil, err
	}
	out := sessions.Outcome(resp.Outcome)
	if out != sessions.OK {
		return out, nil, nil
	}
	sess := sessions.Session{
		UserID: rt.UserID, SessionID: rt.SessionID, RTHash: nextHash, RTPrevHash: presented,
		RotatedAt: time.Now().UnixMilli(), DeviceID: resp.DeviceId, Scope: resp.Scope, CV: resp.CredentialVersion,
		CreatedAt: resp.CreatedAtMs, AbsoluteExp: resp.AbsoluteExpMs,
	}
	if err := s.Core.Sessions.Create(ctx, sess); err != nil {
		return "", nil, err
	}
	slog.Info("session moved", "from", rt.Region, "to", s.Core.Region, "sid", rt.SessionID)
	return sessions.OK, &sess, nil
}

// TakeSession is called by another region moving a session to itself.
func (s *Server) TakeSession(ctx context.Context, req *authv1.TakeSessionRequest) (*authv1.TakeSessionResponse, error) {
	out, sess, err := s.Core.Sessions.Take(ctx, req.UserId, req.SessionId, req.SecretHash)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if out == sessions.Reused {
		if err := s.Core.RevokeSession(ctx, req.UserId, req.SessionId); err != nil {
			slog.Error("revoke reused session", "err", err)
		}
	}
	resp := &authv1.TakeSessionResponse{Outcome: string(out)}
	if sess != nil {
		resp.DeviceId, resp.Scope, resp.CredentialVersion, resp.CreatedAtMs, resp.AbsoluteExpMs = sess.DeviceID, sess.Scope, sess.CV, sess.CreatedAt, sess.AbsoluteExp
	}
	return resp, nil
}

type signoutReq struct {
	RefreshToken string `json:"refresh_token"`
	AllDevices   bool   `json:"all_devices"`
}

// signout always answers 204, even for unknown or already signed-out tokens.
func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req signoutReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	audit := events.Audit{Type: "signout", IP: httpx.ClientIP(r), OK: true}
	if req.AllDevices {
		c, err := s.Authenticate(ctx, httpx.BearerToken(r))
		if err != nil {
			unauthorized(w, "invalid")
			return
		}
		if err := s.Core.RevokeUser(ctx, c.Subject, time.Now().UnixMilli()); err != nil {
			slog.Error("signout all", "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		audit.Type, audit.UserID = "signout_all", c.Subject
		s.Core.Producer.Audit(audit)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rt, err := tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	presented := tokens.HashSecret(rt.Secret)
	deleted, err := s.Core.Sessions.DeleteIfMatch(ctx, rt.UserID, rt.SessionID, presented)
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	switch {
	case deleted:
		if err := s.Core.RevokeSession(ctx, rt.UserID, rt.SessionID); err != nil {
			slog.Error("signout revoke", "err", err)
		}
	case rt.Region != s.Core.Region:
		// The session lives in another region. Ask it, through Kafka, to check
		// the secret and sign the session out; it then publishes the revocation.
		err := s.Core.Producer.Publish(ctx, events.TopicRevocations, rt.UserID, events.Revocation{
			Kind: events.SignoutRequest, UserID: rt.UserID, SessionID: rt.SessionID,
			SecretHash: presented, TargetRegion: rt.Region, At: time.Now().UnixMilli(),
		})
		if err != nil {
			slog.Error("signout request publish", "err", err)
		}
	}
	audit.UserID = rt.UserID
	s.Core.Producer.Audit(audit)
	w.WriteHeader(http.StatusNoContent)
}
