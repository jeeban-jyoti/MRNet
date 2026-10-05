// Package config reads service settings from environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func Str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func MustStr(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("missing required env %s", key))
	}
	return v
}

func Int(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("env %s: %v", key, err))
	}
	return n
}

func Dur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(fmt.Sprintf("env %s: %v", key, err))
	}
	return d
}

// List parses "a,b,c".
func List(key string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(key), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Map parses "k1=v1,k2=v2".
func Map(key string) map[string]string {
	out := map[string]string{}
	for _, p := range List(key) {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			panic(fmt.Sprintf("env %s: bad entry %q", key, p))
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// Key decodes a base64 secret of exactly n bytes.
func Key(key string, n int) []byte {
	b, err := base64.StdEncoding.DecodeString(MustStr(key))
	if err != nil || len(b) != n {
		panic(fmt.Sprintf("env %s must be %d bytes of base64", key, n))
	}
	return b
}
