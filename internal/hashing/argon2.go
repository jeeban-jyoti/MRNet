// Package hashing does Argon2id password hashing with a server-side pepper.
// Only the hasher fleet runs it; other services call the hasher over HTTP.
package hashing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the OWASP minimum for Argon2id: m=19 MiB, t=2, p=1.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeyLen    uint32
	SaltLen   int
}

var Default = Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, KeyLen: 32, SaltLen: 16}

type Hasher struct {
	Pepper []byte // held in KMS in production; never stored with the hashes
	Params Params
}

// peppered HMACs the password first, so a leaked database without the
// pepper cannot be cracked offline.
func (h *Hasher) peppered(password string) []byte {
	m := hmac.New(sha256.New, h.Pepper)
	m.Write([]byte(password))
	return m.Sum(nil)
}

// Hash returns a PHC string: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func (h *Hasher) Hash(password string) (string, error) {
	p := h.Params
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(h.peppered(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

var ErrBadHash = errors.New("unrecognised password hash")

// Verify checks password against a PHC string. needsRehash is true when the
// stored hash used weaker parameters than the current ones.
func (h *Hasher) Verify(password, phc string) (ok, needsRehash bool, err error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, ErrBadHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, false, ErrBadHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, false, ErrBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, ErrBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, false, ErrBadHash
	}
	got := argon2.IDKey(h.peppered(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	needsRehash = p.MemoryKiB < h.Params.MemoryKiB || p.Time < h.Params.Time
	return ok, needsRehash, nil
}
