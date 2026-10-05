package tokens

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"mrnet/internal/keys"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func ToJWKS(ks []keys.Key) JWKS {
	out := JWKS{Keys: []JWK{}}
	for _, k := range ks {
		out.Keys = append(out.Keys, JWK{
			Kty: "OKP", Crv: "Ed25519", Kid: k.Kid, Use: "sig", Alg: "EdDSA",
			X: base64.RawURLEncoding.EncodeToString(k.Public),
		})
	}
	return out
}

// KeySet holds the public keys of every region, fetched from each region's
// JWKS endpoint and refreshed in the background. An unknown kid triggers an
// early refresh, at most once every 5 seconds.
type KeySet struct {
	URLs   []string
	Client *http.Client

	mu        sync.RWMutex
	byURL     map[string]map[string]ed25519.PublicKey
	keys      map[string]ed25519.PublicKey
	lastFetch time.Time
	fetching  sync.Mutex
}

func NewKeySet(urls []string) *KeySet {
	return &KeySet{URLs: urls, Client: &http.Client{Timeout: 3 * time.Second}, keys: map[string]ed25519.PublicKey{}, byURL: map[string]map[string]ed25519.PublicKey{}}
}

// Start does a first fetch (returning an error if no region answered) and
// then refreshes every interval.
func (s *KeySet) Start(ctx context.Context, interval time.Duration) error {
	if n := s.refresh(ctx); n == 0 {
		return fmt.Errorf("jwks: no region reachable")
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refresh(ctx)
			}
		}
	}()
	return nil
}

// refresh replaces each region's keys with what its JWKS lists now, so a key
// removed from a JWKS (rotated out, or leaked) stops validating. A region that
// does not answer keeps its last known keys, so a region outage does not break
// validation of its still-live tokens. It returns how many URLs answered.
func (s *KeySet) refresh(ctx context.Context) int {
	s.fetching.Lock()
	defer s.fetching.Unlock()
	ok := 0
	for _, u := range s.URLs {
		set, err := s.fetch(ctx, u)
		if err != nil {
			slog.Warn("jwks fetch failed", "url", u, "err", err)
			continue
		}
		ok++
		region := map[string]ed25519.PublicKey{}
		for _, k := range set.Keys {
			if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
				continue
			}
			x, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || len(x) != ed25519.PublicKeySize {
				continue
			}
			region[k.Kid] = ed25519.PublicKey(x)
		}
		s.mu.Lock()
		s.byURL[u] = region
		s.mu.Unlock()
	}
	s.mu.Lock()
	merged := map[string]ed25519.PublicKey{}
	for _, region := range s.byURL {
		for kid, pub := range region {
			merged[kid] = pub
		}
	}
	s.keys = merged
	s.lastFetch = time.Now()
	s.mu.Unlock()
	return ok
}

func (s *KeySet) fetch(ctx context.Context, url string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var set JWKS
	return &set, json.NewDecoder(resp.Body).Decode(&set)
}

func (s *KeySet) Key(kid string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	last := s.lastFetch
	s.mu.RUnlock()
	if ok {
		return k, true
	}
	if time.Since(last) < 5*time.Second {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.refresh(ctx)
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok = s.keys[kid]
	return k, ok
}

// StartBackground keeps retrying the first fetch in the background, for
// services that serve their own JWKS and so cannot wait for it at startup.
func (s *KeySet) StartBackground(ctx context.Context, interval time.Duration) {
	go func() {
		for s.refresh(ctx) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refresh(ctx)
			}
		}
	}()
}
