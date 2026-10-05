package tokens

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mrnet/internal/keys"
)

func setup(t testing.TB, region string) (*Issuer, *Verifier, func()) {
	ks := keys.NewStatic(region)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ToJWKS(ks.Published()))
	}))
	set := NewKeySet([]string{srv.URL})
	if n := set.refresh(t.Context()); n != 1 {
		t.Fatal("jwks fetch failed")
	}
	return &Issuer{Region: region, Keys: ks, TTL: 10 * time.Minute}, NewVerifier(set, []string{"ap1", "eu1"}), srv.Close
}

func TestIssueVerify(t *testing.T) {
	iss, v, done := setup(t, "ap1")
	defer done()
	tok, _, err := iss.Issue("user-1", "sess-1", DefaultScp, 3)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.SID != "sess-1" || c.CV != 3 || c.Issuer != "ap1" {
		t.Fatalf("claims %+v", c)
	}
}

func TestRejects(t *testing.T) {
	iss, v, done := setup(t, "ap1")
	defer done()

	expired := &Issuer{Region: "ap1", Keys: iss.Keys, TTL: -time.Minute}
	tok, _, _ := expired.Issue("u", "s", "", 1)
	if _, err := v.Verify(tok); err != ErrExpired {
		t.Fatalf("expired token: %v", err)
	}

	unknownRegion := &Issuer{Region: "zz9", Keys: iss.Keys, TTL: time.Minute}
	tok, _, _ = unknownRegion.Issue("u", "s", "", 1)
	if _, err := v.Verify(tok); err != ErrInvalid {
		t.Fatalf("unknown issuer: %v", err)
	}

	// alg=none must never be accepted.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "u", "sid": "s", "iss": "ap1", "aud": Audience, "exp": time.Now().Add(time.Minute).Unix()})
	none.Header["kid"] = iss.Keys.Current().Kid
	s, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := v.Verify(s); err != ErrInvalid {
		t.Fatalf("alg none: %v", err)
	}

	// Tampered payload.
	good, _, _ := iss.Issue("u", "s", "", 1)
	parts := strings.Split(good, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, err := v.Verify(strings.Join(parts, ".")); err != ErrInvalid {
		t.Fatalf("tampered: %v", err)
	}
}

func TestRefreshRoundTrip(t *testing.T) {
	r := Refresh{Region: "eu1", UserID: "0190-abc", SessionID: NewSessionID(), Secret: NewSecret()}
	got, err := ParseRefresh(r.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Region != r.Region || got.UserID != r.UserID || got.SessionID != r.SessionID || !bytes.Equal(got.Secret, r.Secret) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	for _, bad := range []string{"", "v2.a.b.c.d", "v1.a.b.c", "v1.a.b.c.!!!", "v1..b.c." + strings.Repeat("A", 43)} {
		if _, err := ParseRefresh(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestNextSecretDeterministic(t *testing.T) {
	key, sec := NewSecret(), NewSecret()
	a := NextSecret(key, "sid", sec)
	b := NextSecret(key, "sid", sec)
	c := NextSecret(key, "other", sec)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || len(a) != secretLen {
		t.Fatal("NextSecret must be deterministic per session and 32 bytes")
	}
}

// BenchmarkVerify is the validator's per-request cost with no cache hit.
// Compare against a Rust implementation before switching languages.
func BenchmarkVerify(b *testing.B) {
	iss, v, done := setup(b, "ap1")
	defer done()
	tok, _, _ := iss.Issue("user-1", "sess-1", DefaultScp, 1)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Verify(tok); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkIssue(b *testing.B) {
	iss, _, done := setup(b, "ap1")
	defer done()
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := iss.Issue("user-1", "sess-1", DefaultScp, 1); err != nil {
			b.Fatal(err)
		}
	}
}
