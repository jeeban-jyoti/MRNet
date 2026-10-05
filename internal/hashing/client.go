package hashing

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"

	"mrnet/api/authv1"
	"mrnet/internal/grpcx"
)

// ErrBusy means the hasher pool shed the request (its queue deadline passed).
var ErrBusy = errors.New("hasher busy")

// Client calls the hasher pool over gRPC.
type Client struct {
	C       authv1.HasherClient
	Timeout time.Duration
}

func busy(err error) error {
	if grpcx.Code(err) == codes.ResourceExhausted {
		return ErrBusy
	}
	return err
}

func (c *Client) Hash(ctx context.Context, password string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	res, err := c.C.Hash(ctx, &authv1.HashRequest{Password: password})
	if err != nil {
		return "", busy(err)
	}
	return res.Hash, nil
}

// Verify checks password against hash; an empty hash runs against a dummy.
func (c *Client) Verify(ctx context.Context, password, hash string) (*authv1.VerifyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	res, err := c.C.Verify(ctx, &authv1.VerifyRequest{Password: password, Hash: hash})
	return res, busy(err)
}
