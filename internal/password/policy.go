// Package password holds the password and email rules used at signup and
// password_change.
package password

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MinLen = 10
	MaxLen = 128
)

var (
	ErrTooShort = fmt.Errorf("password must be at least %d characters", MinLen)
	ErrTooLong  = fmt.Errorf("password must be at most %d characters", MaxLen)
	ErrBreached = errors.New("password appears in a known data breach")
	ErrBadEmail = errors.New("invalid email")
)

// NormalizeEmail lowercases and trims the address; the result is the registry key.
func NormalizeEmail(email string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(email))
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || len(e) > 254 {
		return "", ErrBadEmail
	}
	return e, nil
}

func CheckLength(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinLen {
		return ErrTooShort
	}
	if n > MaxLen {
		return ErrTooLong
	}
	return nil
}

// BreachChecker asks a Have I Been Pwned style range API with k-anonymity:
// only the first 5 hex characters of the password's SHA-1 leave the service.
type BreachChecker struct {
	RangeURL string // e.g. https://api.pwnedpasswords.com/range/
	Client   *http.Client
}

func NewBreachChecker(url string) *BreachChecker {
	return &BreachChecker{RangeURL: url, Client: &http.Client{Timeout: 2 * time.Second}}
}

// Breached fails open: if the range service is down, signup is not blocked.
func (b *BreachChecker) Breached(ctx context.Context, pw string) bool {
	if b == nil || b.RangeURL == "" {
		return false
	}
	sum := sha1.Sum([]byte(pw))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.RangeURL+h[:5], nil)
	if err != nil {
		return false
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		slog.Warn("breach check unavailable", "err", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		suffix, _, _ := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if strings.EqualFold(suffix, h[5:]) {
			return true
		}
	}
	return false
}

// Check runs every rule.
func Check(ctx context.Context, b *BreachChecker, pw string) error {
	if err := CheckLength(pw); err != nil {
		return err
	}
	if b.Breached(ctx, pw) {
		return ErrBreached
	}
	return nil
}
