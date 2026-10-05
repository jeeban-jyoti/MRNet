// Package hasher is the hasher pool: it only runs Argon2id. A bounded set of
// workers takes jobs; a job that cannot start within the queue deadline gets
// 429, so a signin flood is shed here and never slows other endpoints.
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

	"mrnet/internal/config"
	"mrnet/internal/hashing"
	"mrnet/internal/httpx"
)

//go:embed breached.txt
var breachedList string

type Server struct {
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

	mux := http.NewServeMux()
	httpx.Health(mux, nil)
	mux.HandleFunc("POST /hash", s.hash)
	mux.HandleFunc("POST /verify", s.verify)
	// Stand-in for the Have I Been Pwned range API, so breach checks work offline.
	mux.HandleFunc("GET /range/{prefix}", s.rangeLookup)
	slog.Info("hasher ready", "workers", workers, "queue_deadline", s.queueDeadline)
	return httpx.Serve(ctx, &http.Server{Addr: config.Str("ADDR", ":8080"), Handler: httpx.Logged("hasher", mux)}, "", "")
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

func (s *Server) hash(w http.ResponseWriter, r *http.Request) {
	var req hashing.HashReq
	if err := httpx.Decode(r, &req); err != nil || req.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	if !s.acquire(r.Context()) {
		w.Header().Set("Retry-After", "1")
		httpx.Error(w, http.StatusTooManyRequests, "busy", "")
		return
	}
	defer s.release()
	h, err := s.H.Hash(req.Password)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal", "")
		return
	}
	httpx.JSON(w, http.StatusOK, hashing.HashResp{Hash: h})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req hashing.VerifyReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	if !s.acquire(r.Context()) {
		w.Header().Set("Retry-After", "1")
		httpx.Error(w, http.StatusTooManyRequests, "busy", "")
		return
	}
	defer s.release()
	hash, dummy := req.Hash, false
	if hash == "" {
		hash, dummy = s.dummy, true
	}
	ok, rehash, err := s.H.Verify(req.Password, hash)
	if err != nil {
		httpx.Error(w, http.StatusUnprocessableEntity, "bad_hash", "")
		return
	}
	httpx.JSON(w, http.StatusOK, hashing.VerifyResp{OK: ok && !dummy, NeedsRehash: rehash})
}

func (s *Server) rangeLookup(w http.ResponseWriter, r *http.Request) {
	p := strings.ToUpper(r.PathValue("prefix"))
	w.Header().Set("Content-Type", "text/plain")
	for _, line := range s.ranges[p] {
		_, _ = w.Write([]byte(line + "\n"))
	}
}
