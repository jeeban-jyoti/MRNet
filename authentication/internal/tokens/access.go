// Package tokens issues and checks MRNet access tokens (Ed25519 JWTs) and
// formats refresh tokens. Every service that needs to check an access token
// uses Verifier, the same code the validator fleet runs.
package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mrnet/authentication/internal/keys"
)

const (
	Audience   = "mrnet"
	ClockSkew  = 30 * time.Second
	DefaultScp = "mr.world"
)

type Claims struct {
	jwt.RegisteredClaims
	SID   string `json:"sid"`
	Scope string `json:"scope"`
	CV    int64  `json:"cv"`
}

// Issuer signs access tokens with the region's current key.
type Issuer struct {
	Region string
	Keys   *keys.Store
	TTL    time.Duration
}

func (i *Issuer) Issue(userID, sessionID, scope string, cv int64) (string, time.Time, error) {
	k := i.Keys.Current()
	now := time.Now()
	exp := now.Add(i.TTL)
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.Region,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        base64.RawURLEncoding.EncodeToString(jti),
		},
		SID:   sessionID,
		Scope: scope,
		CV:    cv,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = k.Kid
	s, err := t.SignedString(k.Private)
	return s, exp, err
}

var (
	ErrExpired = errors.New("expired")
	ErrInvalid = errors.New("invalid")
)

// Verifier checks signature, algorithm, issuer, audience and time claims.
// It does not check revocation; callers do that with their revocation source.
type Verifier struct {
	Keys    *KeySet
	Issuers map[string]bool // accepted iss values (every region)
	parser  *jwt.Parser
}

func NewVerifier(ks *KeySet, regions []string) *Verifier {
	iss := map[string]bool{}
	for _, r := range regions {
		iss[r] = true
	}
	return &Verifier{
		Keys:    ks,
		Issuers: iss,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithAudience(Audience),
			jwt.WithLeeway(ClockSkew),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
		),
	}
}

func (v *Verifier) Verify(token string) (*Claims, error) {
	var c Claims
	_, err := v.parser.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalid
		}
		pub, ok := v.Keys.Key(kid)
		if !ok {
			return nil, ErrInvalid
		}
		return pub, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		return nil, ErrInvalid
	}
	if !v.Issuers[c.Issuer] || c.Subject == "" || c.SID == "" {
		return nil, ErrInvalid
	}
	return &c, nil
}

// HasScope reports whether the space-separated scope list contains want.
func HasScope(scopes, want string) bool {
	if want == "" {
		return true
	}
	for _, s := range strings.Fields(scopes) {
		if s == want {
			return true
		}
	}
	return false
}
