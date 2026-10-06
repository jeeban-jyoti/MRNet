// Package grpcx sets up the gRPC servers and clients services use to call
// each other. Calls carry a shared secret in metadata, standing in for the
// mTLS a real deployment would use.
package grpcx

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const secretKey = "x-internal-token"

// NewServer returns a server that rejects calls without the shared secret.
func NewServer(secret string) *grpc.Server {
	return grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			got := md.Get(secretKey)
			if secret == "" || len(got) != 1 || subtle.ConstantTimeCompare([]byte(got[0]), []byte(secret)) != 1 {
				return nil, status.Error(codes.PermissionDenied, "missing or wrong internal token")
			}
			return h(ctx, req)
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
}

// Serve runs srv on addr until ctx is done, then stops it gracefully.
func Serve(ctx context.Context, addr string, srv *grpc.Server) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		stopped := make(chan struct{})
		go func() { srv.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			srv.Stop()
		}
	}()
	slog.Info("grpc listening", "addr", addr)
	return srv.Serve(lis)
}

type secretCreds string

func (s secretCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{secretKey: string(s)}, nil
}
func (secretCreds) RequireTransportSecurity() bool { return false }

// Dial opens a lazily-connecting client to target (host:port).
func Dial(target, secret string) (*grpc.ClientConn, error) {
	return grpc.NewClient("dns:///"+target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(secretCreds(secret)),
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, PermitWithoutStream: true}),
	)
}

// Code returns the gRPC status code of err (OK for nil).
func Code(err error) codes.Code { return status.Code(err) }
