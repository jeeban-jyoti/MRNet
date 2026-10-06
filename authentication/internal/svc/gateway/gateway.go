// Package gateway is the region's front door (Envoy's job in production):
// TLS 1.3 with HTTP/2, a per-IP rate limit, and routing by path so each
// endpoint lands on the fleet sized for it.
package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mrnet/authentication/internal/config"
	"mrnet/authentication/internal/httpx"
	"mrnet/authentication/internal/infra"
	"mrnet/authentication/internal/ratelimit"
)

func Run(ctx context.Context) error {
	region := config.MustStr("REGION")
	rl, err := infra.Redis(ctx, config.MustStr("REDIS_RL_ADDR"))
	if err != nil {
		return err
	}
	limiter := &ratelimit.Limiter{R: rl}
	perIP := config.Int("IP_LIMIT_PER_MIN", 6000)

	validator := proxy(config.MustStr("VALIDATOR_URL"))
	tokenSvc := proxy(config.MustStr("TOKEN_URL"))
	account := proxy(config.MustStr("ACCOUNT_URL"))
	routes := map[string]http.Handler{
		"/v1/token/validate":     validator,
		"/v1/signin":             tokenSvc,
		"/v1/signout":            tokenSvc,
		"/v1/token/renew":        tokenSvc,
		"/.well-known/jwks.json": tokenSvc,
		"/v1/signup":             account,
		"/v1/password/change":    account,
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-MRNet-Region", region)
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			httpx.Error(w, http.StatusNotFound, "not_found", "")
			return
		}
		up, ok := routes[r.URL.Path]
		if !ok {
			httpx.Error(w, http.StatusNotFound, "not_found", "")
			return
		}
		if ok, wait := limiter.Allow(r.Context(), "rl:ip:"+httpx.ClientIP(r), perIP); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
			httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "")
			return
		}
		up.ServeHTTP(w, r)
	})

	cert, err := selfSigned(region)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              config.Str("ADDR", ":8443"),
		Handler:           httpx.Logged("gateway", h),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Minute, // clients keep HTTP/2 connections open
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	slog.Info("gateway", "region", region, "per_ip_per_min", perIP)
	return httpx.Serve(ctx, srv, "", "")
}

func proxy(target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.SetXForwarded() // inbound X-Forwarded-* is dropped first, so clients cannot spoof their IP
		},
		Transport: &http.Transport{MaxIdleConnsPerHost: 512, IdleConnTimeout: 90 * time.Second},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("upstream error", "path", r.URL.Path, "err", err)
			httpx.Error(w, http.StatusBadGateway, "upstream_unavailable", "")
		},
	}
}

// selfSigned makes a throwaway certificate for local runs. In production the
// certificate comes from the platform's certificate manager.
func selfSigned(region string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: region + ".auth.mrnet.local"},
		DNSNames:     []string{"localhost", region + ".auth.mrnet.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
