package hashing

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"mrnet/internal/httpx"
)

// ErrBusy means the hasher pool shed the request (its queue deadline passed).
var ErrBusy = errors.New("hasher busy")

type Client struct {
	URL string
	C   *httpx.Client
}

type HashReq struct {
	Password string `json:"password"`
}
type HashResp struct {
	Hash string `json:"hash"`
}
type VerifyReq struct {
	Password string `json:"password"`
	Hash     string `json:"hash"` // empty: verify against a dummy hash, to keep timing equal
}
type VerifyResp struct {
	OK          bool `json:"ok"`
	NeedsRehash bool `json:"needs_rehash"`
}

func (c *Client) Hash(ctx context.Context, password string) (string, error) {
	var out HashResp
	st, eb, err := c.C.PostJSON(ctx, c.URL+"/hash", HashReq{Password: password}, &out)
	if err != nil {
		return "", err
	}
	if st == http.StatusTooManyRequests {
		return "", ErrBusy
	}
	if eb != nil {
		return "", fmt.Errorf("hasher: %d %s", st, eb.Error)
	}
	return out.Hash, nil
}

func (c *Client) Verify(ctx context.Context, password, hash string) (VerifyResp, error) {
	var out VerifyResp
	st, eb, err := c.C.PostJSON(ctx, c.URL+"/verify", VerifyReq{Password: password, Hash: hash}, &out)
	if err != nil {
		return out, err
	}
	if st == http.StatusTooManyRequests {
		return out, ErrBusy
	}
	if eb != nil {
		return out, fmt.Errorf("hasher: %d %s", st, eb.Error)
	}
	return out, nil
}
