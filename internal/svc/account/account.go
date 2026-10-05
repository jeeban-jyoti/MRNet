// Package account is the account service: signup and password_change, the
// low-volume calls that write credentials. It also relays the credentials
// outbox to Kafka, so other regions get a copy of every user homed here.
package account

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mrnet/api/authv1"
	"mrnet/internal/authcore"
	"mrnet/internal/config"
	"mrnet/internal/events"
	"mrnet/internal/grpcx"
	"mrnet/internal/hashing"
	"mrnet/internal/httpx"
	"mrnet/internal/password"
	"mrnet/internal/ratelimit"
	"mrnet/internal/registry"
	"mrnet/internal/tokens"
	"mrnet/internal/users"
)

type Server struct {
	authv1.UnimplementedAccountsServer
	*authcore.Deps
	breach      *password.BreachChecker
	signupPerIP int
}

func Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d, err := authcore.Connect(ctx)
	if err != nil {
		return err
	}
	s := &Server{
		Deps:        d,
		breach:      password.NewBreachChecker(config.Str("BREACH_RANGE_URL", "")),
		signupPerIP: config.Int("SIGNUP_PER_IP_PER_MIN", 30),
	}
	go users.RunOutbox(ctx, d.Primary, d.Core.Producer, 100*time.Millisecond, func(err error) {
		slog.Warn("outbox relay", "err", err)
	})

	mux := http.NewServeMux()
	httpx.Health(mux, nil)
	mux.HandleFunc("POST /v1/signup", s.signup)
	mux.HandleFunc("POST /v1/password/change", s.passwordChange)

	gs := grpcx.NewServer(d.InternalSecret)
	authv1.RegisterAccountsServer(gs, s)
	errc := make(chan error, 2)
	go func() { errc <- grpcx.Serve(ctx, config.Str("GRPC_ADDR", ":9090"), gs) }()
	go func() {
		errc <- httpx.Serve(ctx, &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: httpx.Logged("account", mux)}, "", "")
	}()
	return <-errc
}

type signupReq struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	DeviceID    string `json:"device_id"`
}

type signupResp struct {
	UserID string `json:"user_id"`
	tokens.Pair
}

func policyError(w http.ResponseWriter, err error) {
	code := "weak_password"
	if errors.Is(err, password.ErrBreached) {
		code = "breached_password"
	}
	httpx.Error(w, http.StatusUnprocessableEntity, code, err.Error())
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req signupReq
	if err := httpx.Decode(r, &req); err != nil || req.Email == "" || req.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "email and password are required")
		return
	}
	ip := httpx.ClientIP(r)
	if ok, _ := s.Limiter.Allow(ctx, "rl:ip:signup:"+ip, s.signupPerIP); !ok {
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "")
		return
	}
	email, err := password.NormalizeEmail(req.Email)
	if err != nil {
		httpx.Error(w, http.StatusUnprocessableEntity, "invalid_email", "")
		return
	}
	if err := password.Check(ctx, s.breach, req.Password); err != nil {
		policyError(w, err)
		return
	}
	hash, err := s.Hasher.Hash(ctx, req.Password)
	if errors.Is(err, hashing.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		httpx.Error(w, http.StatusTooManyRequests, "busy", "")
		return
	}
	if err != nil {
		slog.Error("signup hash", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}

	uid, _ := uuid.NewV7()
	now := time.Now().UTC()
	// The global registry decides who owns the email, across all regions.
	if err := s.Registry.Claim(ctx, email, uid.String(), s.Core.Region); err != nil {
		if errors.Is(err, registry.ErrTaken) {
			httpx.Error(w, http.StatusConflict, "email_taken", "")
			return
		}
		slog.Error("signup registry", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	u := &users.User{
		UserID: uid.String(), EmailNorm: email, PasswordHash: hash, CredentialVersion: 1, Status: "active",
		HomeRegion: s.Core.Region, DisplayName: req.DisplayName, PasswordChangedAt: now, CreatedAt: now,
	}
	if err := users.Insert(ctx, s.Primary, u); err != nil {
		_ = s.Registry.Release(context.WithoutCancel(ctx), email, u.UserID)
		if errors.Is(err, users.ErrEmailTaken) {
			httpx.Error(w, http.StatusConflict, "email_taken", "")
			return
		}
		slog.Error("signup insert", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	pair, _, err := s.Core.NewSession(ctx, u.UserID, req.DeviceID, tokens.DefaultScp, u.CredentialVersion)
	if err != nil {
		slog.Error("signup session", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	s.Core.Producer.Audit(events.Audit{Type: "signup", UserID: u.UserID, OK: true, IP: ip, DeviceID: req.DeviceID})
	httpx.JSON(w, http.StatusCreated, signupResp{UserID: u.UserID, Pair: pair})
}

type changeReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// HomeChangeReq / HomeChangeResp are a password change as the home region runs it.
type HomeChangeReq struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
}

type HomeChangeResp struct {
	CredentialVersion int64
	RevokedBeforeMs   int64
}

// HTTP status <-> gRPC code for errors crossing regions; the error code
// string (wrong_password, ...) travels as the status message.
var toGRPC = map[int]codes.Code{
	http.StatusUnauthorized:        codes.Unauthenticated,
	http.StatusTooManyRequests:     codes.ResourceExhausted,
	http.StatusConflict:            codes.Aborted,
	http.StatusMisdirectedRequest:  codes.FailedPrecondition,
	http.StatusServiceUnavailable:  codes.Unavailable,
	http.StatusUnprocessableEntity: codes.InvalidArgument,
}

func (s *Server) passwordChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, err := s.Authenticate(ctx, httpx.BearerToken(r))
	if err != nil {
		reason := "invalid"
		if errors.Is(err, tokens.ErrExpired) {
			reason = "expired"
		} else if errors.Is(err, authcore.ErrRevoked) {
			reason = "revoked"
		}
		httpx.Error(w, http.StatusUnauthorized, reason, "")
		return
	}
	var req changeReq
	if err := httpx.Decode(r, &req); err != nil || req.CurrentPassword == "" || req.NewPassword == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "current_password and new_password are required")
		return
	}
	if err := password.Check(ctx, s.breach, req.NewPassword); err != nil {
		policyError(w, err)
		return
	}
	// Read this device's session before every older session is revoked.
	device := ""
	if sess, err := s.Core.Sessions.Get(ctx, claims.Subject, claims.SID); err == nil && sess != nil {
		device = sess.DeviceID
	}

	home, err := s.homeOf(ctx, claims.Subject)
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	var res HomeChangeResp
	var status int
	var code string
	if home == s.Core.Region {
		res, status, code = s.changeAtHome(ctx, HomeChangeReq{UserID: claims.Subject, CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword})
	} else {
		res, status, code = s.forwardChange(ctx, home, HomeChangeReq{UserID: claims.Subject, CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword})
		if status == http.StatusOK {
			// The home region publishes the user-level revocation for every
			// region; apply it here now so this region does not wait for Kafka.
			if err := s.Core.RevokeUserLocal(ctx, claims.Subject, res.RevokedBeforeMs); err != nil {
				slog.Error("local revoke after change", "err", err)
			}
		}
	}
	if status != http.StatusOK {
		httpx.Error(w, status, code, "")
		return
	}
	pair, _, err := s.Core.NewSession(ctx, claims.Subject, device, claims.Scope, res.CredentialVersion)
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	s.Core.Producer.Audit(events.Audit{Type: "password_change", UserID: claims.Subject, OK: true, IP: httpx.ClientIP(r), DeviceID: device})
	httpx.JSON(w, http.StatusOK, pair)
}

func (s *Server) homeOf(ctx context.Context, uid string) (string, error) {
	u, err := users.ByID(ctx, s.Primary, uid)
	if err == nil {
		return u.HomeRegion, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		return "", err
	}
	return s.Registry.HomeOf(ctx, uid)
}

func (s *Server) forwardChange(ctx context.Context, home string, req HomeChangeReq) (HomeChangeResp, int, string) {
	var res HomeChangeResp
	peer, ok := s.PeerAccounts[home]
	if !ok {
		return res, http.StatusServiceUnavailable, "home_region_unknown"
	}
	ctx, cancel := context.WithTimeout(ctx, s.PeerTimeout)
	defer cancel()
	out, err := peer.ChangePassword(ctx, &authv1.ChangePasswordRequest{UserId: req.UserID, CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword})
	if err != nil {
		st := status.Convert(err)
		for httpStatus, c := range toGRPC {
			if c == st.Code() && c != codes.Unavailable {
				return res, httpStatus, st.Message()
			}
		}
		slog.Warn("password change forward failed", "home", home, "err", err)
		return res, http.StatusServiceUnavailable, "home_region_unavailable"
	}
	return HomeChangeResp{CredentialVersion: out.CredentialVersion, RevokedBeforeMs: out.RevokedBeforeMs}, http.StatusOK, ""
}

// ChangePassword is a password change forwarded here, the user's home region.
func (s *Server) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	res, st, code := s.changeAtHome(ctx, HomeChangeReq{UserID: req.UserId, CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword})
	if st != http.StatusOK {
		c, ok := toGRPC[st]
		if !ok {
			c = codes.Internal
		}
		return nil, status.Error(c, code)
	}
	return &authv1.ChangePasswordResponse{CredentialVersion: res.CredentialVersion, RevokedBeforeMs: res.RevokedBeforeMs}, nil
}

// changeAtHome runs in the user's home region, the only one that writes the account.
func (s *Server) changeAtHome(ctx context.Context, req HomeChangeReq) (HomeChangeResp, int, string) {
	var res HomeChangeResp
	u, err := users.ByID(ctx, s.Primary, req.UserID)
	if err != nil {
		return res, http.StatusUnauthorized, "invalid"
	}
	if u.HomeRegion != s.Core.Region {
		return res, http.StatusMisdirectedRequest, "not_home_region"
	}
	acct := ratelimit.EmailKey(u.EmailNorm)
	if s.Limiter.AccountDelay(ctx, acct) > 0 {
		return res, http.StatusTooManyRequests, "rate_limited"
	}
	v, err := s.Hasher.Verify(ctx, req.CurrentPassword, u.PasswordHash)
	if errors.Is(err, hashing.ErrBusy) {
		return res, http.StatusTooManyRequests, "busy"
	}
	if err != nil {
		return res, http.StatusServiceUnavailable, "unavailable"
	}
	if !v.Ok {
		s.Limiter.AccountFailed(ctx, acct)
		return res, http.StatusUnauthorized, "wrong_password"
	}
	newHash, err := s.Hasher.Hash(ctx, req.NewPassword)
	if err != nil {
		return res, http.StatusServiceUnavailable, "unavailable"
	}
	nu, err := users.ChangePassword(ctx, s.Primary, u.UserID, newHash, u.CredentialVersion)
	if errors.Is(err, users.ErrNotFound) {
		return res, http.StatusConflict, "concurrent_change"
	}
	if err != nil {
		return res, http.StatusServiceUnavailable, "unavailable"
	}
	before := time.Now().UnixMilli()
	if err := s.Core.RevokeUser(ctx, u.UserID, before); err != nil {
		slog.Error("revoke after password change", "err", err)
		return res, http.StatusServiceUnavailable, "unavailable"
	}
	return HomeChangeResp{CredentialVersion: nu.CredentialVersion, RevokedBeforeMs: before}, http.StatusOK, ""
}

// GetUserByEmail serves another region's signin for a user homed here
// whose credentials have not been copied there yet.
func (s *Server) GetUserByEmail(ctx context.Context, req *authv1.GetUserByEmailRequest) (*authv1.User, error) {
	u, err := users.ByEmail(ctx, s.Primary, req.EmailNorm)
	if errors.Is(err, users.ErrNotFound) || (err == nil && u.HomeRegion != s.Core.Region) {
		return nil, status.Error(codes.NotFound, "not homed here")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return users.ToProto(u), nil
}
