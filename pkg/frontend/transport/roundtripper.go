package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/httpgrpc/server"
)

// GrpcRoundTripper is similar to http.RoundTripper, but works with HTTP requests converted to protobuf messages.
type GrpcRoundTripper interface {
	RoundTripGRPC(context.Context, *httpgrpc.HTTPRequest) (*httpgrpc.HTTPResponse, error)
}

func AdaptGrpcRoundTripperToHTTPRoundTripper(r GrpcRoundTripper) http.RoundTripper {
	return &grpcRoundTripperAdapter{roundTripper: r}
}

// This adapter wraps GrpcRoundTripper and converted it into http.RoundTripper
type grpcRoundTripperAdapter struct {
	roundTripper GrpcRoundTripper
}

type buffer struct {
	buff []byte
	io.ReadCloser
}

func (b *buffer) Bytes() []byte {
	return b.buff
}

func (a *grpcRoundTripperAdapter) RoundTrip(r *http.Request) (*http.Response, error) {
	// Strip end-user authentication/authorization headers before converting
	// the request into an httpgrpc.HTTPRequest. These headers are propagated
	// into the queued request that the scheduler hands to a querier; a
	// compromised or rogue querier (or any other component holding a queued
	// request) must never be given gateway-forwarded end-user credentials.
	// The downstream querier only needs the tenant identity (X-Scope-OrgID),
	// standard content negotiation, and tracing headers, all of which are
	// preserved by server.HTTPRequest.
	r = stripSensitiveRequestHeaders(r)
	req, err := server.HTTPRequest(r)
	if err != nil {
		return nil, err
	}

	resp, err := a.roundTripper.RoundTripGRPC(r.Context(), req)
	if err != nil {
		return nil, err
	}

	httpResp := &http.Response{
		StatusCode:    int(resp.Code),
		Body:          &buffer{buff: resp.Body, ReadCloser: io.NopCloser(bytes.NewReader(resp.Body))},
		Header:        http.Header{},
		ContentLength: int64(len(resp.Body)),
	}
	for _, h := range resp.Headers {
		httpResp.Header[h.Key] = h.Values
	}
	return httpResp, nil
}

// sensitiveRequestHeaders are stripped from the HTTP request before it is
// converted to the httpgrpc form that is queued for the querier. This stops
// gateway-forwarded end-user credentials (Authorization, Cookie,
// Proxy-Authorization) from being handed to any component that dequeues the
// request from the scheduler.
var sensitiveRequestHeaders = []string{
	"Authorization",
	"Cookie",
	"Proxy-Authorization",
}

func stripSensitiveRequestHeaders(r *http.Request) *http.Request {
	if r == nil || r.Header == nil {
		return r
	}
	// Only clone when we actually need to mutate headers.
	needsClone := false
	for _, h := range sensitiveRequestHeaders {
		if len(r.Header.Values(h)) > 0 {
			needsClone = true
			break
		}
	}
	if !needsClone {
		return r
	}
	cloned := r.Clone(r.Context())
	for _, h := range sensitiveRequestHeaders {
		cloned.Header.Del(h)
	}
	return cloned
}
