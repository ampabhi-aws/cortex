package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/httpgrpc/server"
)

// sensitiveInboundHeaders are stripped from the request headers before the
// request is forwarded over gRPC to a querier. The querier does not need
// these to execute the query, and forwarding them would leak end-user
// credentials to the (potentially large) set of querier workers.
var sensitiveInboundHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
}

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
	// Strip sensitive inbound headers before forwarding the request to a
	// querier. r.Header is shared with the caller, so clone it rather than
	// mutating it in place.
	if r.Header != nil && containsAnyHeader(r.Header, sensitiveInboundHeaders) {
		rCopy := *r
		rCopy.Header = r.Header.Clone()
		for _, h := range sensitiveInboundHeaders {
			rCopy.Header.Del(h)
		}
		r = &rCopy
	}

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

// containsAnyHeader reports whether h contains any of the given header
// names (case-insensitively, via http.Header's canonicalisation).
func containsAnyHeader(h http.Header, names []string) bool {
	for _, n := range names {
		if _, ok := h[http.CanonicalHeaderKey(n)]; ok {
			return true
		}
	}
	return false
}
