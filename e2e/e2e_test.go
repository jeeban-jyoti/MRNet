//go:build e2e

// End-to-end tests against the two local regions started by `make up`.
// Run with `make e2e`.
package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	ap1 = env("AP1_URL", "https://localhost:8443")
	eu1 = env("EU1_URL", "https://localhost:9443")
	hc  = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // local self-signed gateway certs
		ForceAttemptHTTP2: true,
	}}
)

const pw = "orbiting-quokka-42"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type pair struct {
	UserID           string `json:"user_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int64  `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

type resp struct {
	Status int
	Body   map[string]any
	Header http.Header
	raw    []byte
}

func (r resp) pair(t *testing.T) pair {
	t.Helper()
	var p pair
	if err := json.Unmarshal(r.raw, &p); err != nil || p.AccessToken == "" {
		t.Fatalf("no token pair in %d %s", r.Status, r.raw)
	}
	return p
}

func post(t *testing.T, base, path string, body any, bearer string) resp {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatalf("POST %s%s: %v", base, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, raw: raw}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func expect(t *testing.T, r resp, status int, errCode string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("want %d, got %d: %s", status, r.Status, r.raw)
	}
	if errCode != "" && r.Body["error"] != errCode {
		t.Fatalf("want error %q, got %s", errCode, r.raw)
	}
}

func email(t *testing.T) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return strings.ToLower(t.Name()[4:]) + "-" + hex.EncodeToString(b) + "@mrnet.dev"
}

func signup(t *testing.T, base, mail string) pair {
	t.Helper()
	r := post(t, base, "/v1/signup", map[string]string{"email": mail, "password": pw, "display_name": "Test", "device_id": "quest-" + base[len(base)-4:]}, "")
	expect(t, r, http.StatusCreated, "")
	return r.pair(t)
}

func validate(t *testing.T, base, at string) resp {
	return post(t, base, "/v1/token/validate", map[string]string{"access_token": at}, "")
}

// eventually retries f until it returns true; cross-region effects ride Kafka.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestSignupAndValidateEverywhere(t *testing.T) {
	mail := email(t)
	p := signup(t, ap1, mail)
	if p.UserID == "" || p.AccessExpiresIn < 590 || p.RefreshExpiresIn != 30*24*3600 || !strings.HasPrefix(p.RefreshToken, "v1.ap1.") {
		t.Fatalf("unexpected pair %+v", p)
	}
	for _, base := range []string{ap1, eu1} {
		r := validate(t, base, p.AccessToken)
		expect(t, r, http.StatusOK, "")
		if r.Body["sub"] != p.UserID || r.Body["iss"] != "ap1" {
			t.Fatalf("validate in %s: %s", base, r.raw)
		}
	}
	expect(t, post(t, eu1, "/v1/token/validate", map[string]string{"access_token": p.AccessToken, "required_scope": "admin"}, ""), http.StatusForbidden, "insufficient_scope")
	expect(t, validate(t, ap1, p.AccessToken[:len(p.AccessToken)-4]+"AAAA"), http.StatusUnauthorized, "invalid")
}

func TestSignupRules(t *testing.T) {
	mail := email(t)
	signup(t, ap1, mail)
	// The global registry stops the same email in another region, even before credentials replicate.
	expect(t, post(t, eu1, "/v1/signup", map[string]string{"email": strings.ToUpper(mail), "password": pw}, ""), http.StatusConflict, "email_taken")
	expect(t, post(t, ap1, "/v1/signup", map[string]string{"email": email(t), "password": "short"}, ""), http.StatusUnprocessableEntity, "weak_password")
	expect(t, post(t, ap1, "/v1/signup", map[string]string{"email": email(t), "password": "password1234"}, ""), http.StatusUnprocessableEntity, "breached_password")
	expect(t, post(t, ap1, "/v1/signup", map[string]string{"email": "not-an-email", "password": pw}, ""), http.StatusUnprocessableEntity, "invalid_email")
}

func TestSigninAnyRegion(t *testing.T) {
	mail := email(t)
	signup(t, ap1, mail)
	// Right after signup: eu1 has no copy yet in the worst case and falls back to the home region.
	for _, base := range []string{ap1, eu1} {
		r := post(t, base, "/v1/signin", map[string]string{"email": mail, "password": pw, "device_id": "d"}, "")
		expect(t, r, http.StatusOK, "")
		p := r.pair(t)
		region := map[string]string{ap1: "ap1", eu1: "eu1"}[base]
		if !strings.HasPrefix(p.RefreshToken, "v1."+region+".") {
			t.Fatalf("session should live where the user signed in: %s", p.RefreshToken)
		}
	}
	wrong := post(t, eu1, "/v1/signin", map[string]string{"email": mail, "password": "not-the-password"}, "")
	unknown := post(t, eu1, "/v1/signin", map[string]string{"email": "nobody-" + mail, "password": "not-the-password"}, "")
	expect(t, wrong, http.StatusUnauthorized, "invalid_credentials")
	expect(t, unknown, http.StatusUnauthorized, "invalid_credentials")
	if string(wrong.raw) != string(unknown.raw) {
		t.Fatalf("unknown email and wrong password must look identical: %s vs %s", wrong.raw, unknown.raw)
	}
}

func TestRenewRotationRetryAndReuse(t *testing.T) {
	p := signup(t, ap1, email(t))
	r1 := post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, "")
	expect(t, r1, http.StatusOK, "")
	p1 := r1.pair(t)
	if p1.RefreshToken == p.RefreshToken {
		t.Fatal("renew must rotate the refresh token")
	}
	// A client retry with the old token inside 10 s gets the same new refresh token.
	r2 := post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, "")
	expect(t, r2, http.StatusOK, "")
	if r2.pair(t).RefreshToken != p1.RefreshToken {
		t.Fatal("retry must return the same new refresh token")
	}
	// Normal use continues.
	p2 := post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p1.RefreshToken}, "").pair(t)
	// Replaying a token two rotations old is theft: the whole session dies.
	expect(t, post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusUnauthorized, "reused")
	expect(t, post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p2.RefreshToken}, ""), http.StatusUnauthorized, "revoked")
	for _, base := range []string{ap1, eu1} {
		eventually(t, "killed session's access token revoked in "+base, func() bool {
			r := validate(t, base, p2.AccessToken)
			return r.Status == http.StatusUnauthorized && r.Body["error"] == "revoked"
		})
	}
}

func TestRenewMovesSessionAcrossRegions(t *testing.T) {
	p := signup(t, ap1, email(t))
	r := post(t, eu1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, "")
	expect(t, r, http.StatusOK, "")
	moved := r.pair(t)
	if !strings.HasPrefix(moved.RefreshToken, "v1.eu1.") {
		t.Fatalf("session should now live in eu1: %s", moved.RefreshToken)
	}
	// Retry of the move inside the grace window returns the same token.
	again := post(t, eu1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, "")
	expect(t, again, http.StatusOK, "")
	if again.pair(t).RefreshToken != moved.RefreshToken {
		t.Fatal("retried move must return the same token")
	}
	// ap1 no longer holds it; renewing in eu1 needs no cross-region call.
	expect(t, post(t, eu1, "/v1/token/renew", map[string]string{"refresh_token": moved.RefreshToken}, ""), http.StatusOK, "")
}

func TestSignout(t *testing.T) {
	p := signup(t, ap1, email(t))
	expect(t, post(t, ap1, "/v1/signout", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusNoContent, "")
	expect(t, post(t, ap1, "/v1/signout", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusNoContent, "")
	expect(t, post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusUnauthorized, "revoked")
	for _, base := range []string{ap1, eu1} {
		eventually(t, "signed-out access token revoked in "+base, func() bool {
			return validate(t, base, p.AccessToken).Status == http.StatusUnauthorized
		})
	}
}

func TestSignoutFromOtherRegion(t *testing.T) {
	p := signup(t, ap1, email(t))
	// Signing out in eu1 a session that lives in ap1 goes through Kafka.
	expect(t, post(t, eu1, "/v1/signout", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusNoContent, "")
	eventually(t, "remote signout reaches ap1", func() bool {
		return validate(t, eu1, p.AccessToken).Status == http.StatusUnauthorized
	})
	expect(t, post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": p.RefreshToken}, ""), http.StatusUnauthorized, "revoked")
}

func TestSignoutAllDevices(t *testing.T) {
	mail := email(t)
	home := signup(t, ap1, mail)
	away := post(t, eu1, "/v1/signin", map[string]string{"email": mail, "password": pw}, "").pair(t)
	expect(t, post(t, eu1, "/v1/signout", map[string]any{"all_devices": true}, ""), http.StatusUnauthorized, "")
	time.Sleep(1100 * time.Millisecond) // tokens issued in an earlier second than the revocation
	expect(t, post(t, eu1, "/v1/signout", map[string]any{"all_devices": true}, away.AccessToken), http.StatusNoContent, "")
	for _, p := range []pair{home, away} {
		for _, base := range []string{ap1, eu1} {
			eventually(t, "all sessions revoked", func() bool { return validate(t, base, p.AccessToken).Status == http.StatusUnauthorized })
		}
	}
	eventually(t, "ap1 session deleted", func() bool {
		return post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": home.RefreshToken}, "").Status == http.StatusUnauthorized
	})
	expect(t, post(t, eu1, "/v1/token/renew", map[string]string{"refresh_token": away.RefreshToken}, ""), http.StatusUnauthorized, "")
}

func TestPasswordChangeAwayFromHome(t *testing.T) {
	mail := email(t)
	home := signup(t, ap1, mail)
	away := post(t, eu1, "/v1/signin", map[string]string{"email": mail, "password": pw, "device_id": "travel-quest"}, "").pair(t)
	time.Sleep(1100 * time.Millisecond)
	newPw := "nebula-otter-1337"

	expect(t, post(t, eu1, "/v1/password/change", map[string]string{"current_password": "wrong-password-x", "new_password": newPw}, away.AccessToken), http.StatusUnauthorized, "wrong_password")
	expect(t, post(t, eu1, "/v1/password/change", map[string]string{"current_password": pw, "new_password": "qwerty123"}, away.AccessToken), http.StatusUnprocessableEntity, "")

	// eu1 forwards to the home region (ap1) and hands back a fresh pair for this device.
	r := post(t, eu1, "/v1/password/change", map[string]string{"current_password": pw, "new_password": newPw}, away.AccessToken)
	expect(t, r, http.StatusOK, "")
	fresh := r.pair(t)
	expect(t, validate(t, eu1, fresh.AccessToken), http.StatusOK, "")

	// Every older session, in both regions, is dead.
	for _, p := range []pair{home, away} {
		for _, base := range []string{ap1, eu1} {
			eventually(t, "old tokens revoked", func() bool { return validate(t, base, p.AccessToken).Status == http.StatusUnauthorized })
		}
	}
	expect(t, post(t, ap1, "/v1/token/renew", map[string]string{"refresh_token": home.RefreshToken}, ""), http.StatusUnauthorized, "")
	expect(t, post(t, eu1, "/v1/token/renew", map[string]string{"refresh_token": fresh.RefreshToken}, ""), http.StatusOK, "")

	// The new hash is copied to every region.
	for _, base := range []string{ap1, eu1} {
		eventually(t, "new password works in "+base, func() bool {
			return post(t, base, "/v1/signin", map[string]string{"email": mail, "password": newPw}, "").Status == http.StatusOK
		})
		expect(t, post(t, base, "/v1/signin", map[string]string{"email": mail, "password": pw}, ""), http.StatusUnauthorized, "invalid_credentials")
	}
}

func TestSigninThrottleNoLockout(t *testing.T) {
	mail := email(t)
	signup(t, ap1, mail)
	var last resp
	for i := 0; i < 8; i++ {
		last = post(t, ap1, "/v1/signin", map[string]string{"email": mail, "password": "definitely-wrong"}, "")
		if last.Status == http.StatusTooManyRequests {
			break
		}
	}
	expect(t, last, http.StatusTooManyRequests, "rate_limited")
	if last.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

func TestJWKSListsEveryRegion(t *testing.T) {
	res, err := hc.Get(ap1 + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var set struct {
		Keys []struct{ Kid, Alg, Crv string }
	}
	_ = json.NewDecoder(res.Body).Decode(&set)
	if len(set.Keys) == 0 || set.Keys[0].Alg != "EdDSA" || set.Keys[0].Crv != "Ed25519" {
		t.Fatalf("bad jwks %+v", set)
	}
	if res.Header.Get("X-MRNet-Region") != "ap1" {
		t.Fatal("gateway should tag responses with its region")
	}
}
