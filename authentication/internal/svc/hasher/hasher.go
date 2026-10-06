// Package hasher is the hasher pool: it only runs Argon2id, served over gRPC.
// A bounded set of workers takes jobs; a job that cannot start within the
// queue deadline gets RESOURCE_EXHAUSTED (429 to the client), so a signin
// flood is shed here and never slows other endpoints.
package hasher

import (
	"bufio"
	"context"
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mrnet/authentication/api/authv1"
	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/grpcx"
	"mrnet/authentication/internal/hashing"
	"mrnet/authentication/internal/httpx"
)

//go:embed breached.txt
var breachedList string

type Server struct {
	authv1.UnimplementedHasherServer
	H             *hashing.Hasher
	slots         chan struct{}
	queueDeadline time.Duration
	dummy         string
	ranges        map[string][]string // sha1 prefix -> suffixes (mock HIBP)
}

func Run(ctx context.Context) error {
	workers := config.Int("HASHER_WORKERS", runtime.GOMAXPROCS(0))
	s := &Server{
		H:             &hashing.Hasher{Pepper: config.Key("HASH_PEPPER", 32), Params: hashing.Default},
		slots:         make(chan struct{}, workers),
		queueDeadline: config.Dur("HASHER_QUEUE_DEADLINE", 500*time.Millisecond),
		ranges:        map[string][]string{},
	}
	var err error
	if s.dummy, err = s.H.Hash("dummy-password-for-timing"); err != nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(breachedList))
	for sc.Scan() {
		if pw := strings.TrimSpace(sc.Text()); pw != "" {
			sum := sha1.Sum([]byte(pw))
			h := strings.ToUpper(hex.EncodeToString(sum[:]))
			s.ranges[h[:5]] = append(s.ranges[h[:5]], h[5:]+":1")
		}
	}

	gs := grpcx.NewServer(config.MustStr("INTERNAL_SECRET"))
	authv1.RegisterHasherServer(gs, s)
	errc := make(chan error, 2)
	go func() { errc <- grpcx.Serve(ctx, config.Str("GRPC_ADDR", ":9090"), gs) }()

	// HTTP is only for health probes and the breach-check stand-in.
	mux := http.NewServeMux()
	httpx.Health(mux, nil)
	// Stand-in for the Have I Been Pwned range API, so breach checks work offline.
	mux.HandleFunc("GET /range/{prefix}", s.rangeLookup)
	slog.Info("hasher ready", "workers", workers, "queue_deadline", s.queueDeadline)
	go func() {
		errc <- httpx.Serve(ctx, &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: httpx.Logged("hasher", mux)}, "", "")
	}()
	return <-errc
}

// acquire waits for a worker slot until the queue deadline.
func (s *Server) acquire(ctx context.Context) bool {
	t := time.NewTimer(s.queueDeadline)
	defer t.Stop()
	select {
	case s.slots <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (s *Server) release() { <-s.slots }

var errBusy = status.Error(codes.ResourceExhausted, "hasher queue deadline passed")

func (s *Server) Hash(ctx context.Context, req *authv1.HashRequest) (*authv1.HashResponse, error) {
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if !s.acquire(ctx) {
		return nil, errBusy
	}
	defer s.release()
	h, err := s.H.Hash(req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &authv1.HashResponse{Hash: h}, nil
}

func (s *Server) Verify(ctx context.Context, req *authv1.VerifyRequest) (*authv1.VerifyResponse, error) {
	if !s.acquire(ctx) {
		return nil, errBusy
	}
	defer s.release()
	hash, dummy := req.Hash, false
	if hash == "" {
		hash, dummy = s.dummy, true
	}
	ok, rehash, err := s.H.Verify(req.Password, hash)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &authv1.VerifyResponse{Ok: ok && !dummy, NeedsRehash: rehash}, nil
}

func (s *Server) rangeLookup(w http.ResponseWriter, r *http.Request) {
	p := strings.ToUpper(r.PathValue("prefix"))
	w.Header().Set("Content-Type", "text/plain")
	for _, line := range s.ranges[p] {
		_, _ = w.Write([]byte(line + "\n"))
	}
}
