package tokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	RefreshTTL      = 30 * 24 * time.Hour // sliding
	RefreshAbsolute = 90 * 24 * time.Hour
	RetryGrace      = 10 * time.Second
	secretLen       = 32
)

// Refresh is v1.<region>.<user_id>.<session_id>.<secret>. The region says
// where the session lives; the user id routes straight to the Redis shard.
type Refresh struct {
	Region    string
	UserID    string
	SessionID string
	Secret    []byte
}

func (r Refresh) String() string {
	return strings.Join([]string{"v1", r.Region, r.UserID, r.SessionID,
		base64.RawURLEncoding.EncodeToString(r.Secret)}, ".")
}

var ErrMalformed = errors.New("malformed refresh token")

func ParseRefresh(s string) (Refresh, error) {
	p := strings.Split(s, ".")
	if len(p) != 5 || p[0] != "v1" || p[1] == "" || p[2] == "" || p[3] == "" {
		return Refresh{}, ErrMalformed
	}
	sec, err := base64.RawURLEncoding.DecodeString(p[4])
	if err != nil || len(sec) != secretLen {
		return Refresh{}, ErrMalformed
	}
	return Refresh{Region: p[1], UserID: p[2], SessionID: p[3], Secret: sec}, nil
}

func NewSecret() []byte {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func NewSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HashSecret is what the session store keeps; the secret itself is never stored.
func HashSecret(secret []byte) string {
	h := sha256.Sum256(secret)
	return hex.EncodeToString(h[:])
}

// NextSecret derives the rotated secret from the presented one. Because it is
// deterministic, a client that retries a renew within the grace window gets
// the very same new refresh token back without the server storing it.
func NextSecret(rotationKey []byte, sessionID string, secret []byte) []byte {
	m := hmac.New(sha256.New, rotationKey)
	m.Write([]byte(sessionID))
	m.Write([]byte{0})
	m.Write(secret)
	return m.Sum(nil)
}

// Pair is the response body of every token-issuing endpoint.
type Pair struct {
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int64  `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}
