package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/httpgrpc/server"
)

// stripCredentialHeaders removes HTTP headers that carry end-user credentials
// (Authorization, Cookie, Proxy-Authorization) from an httpgrpc.HTTPRequest.
//
// The query-frontend forwards the inbound HTTP request to queriers over a gRPC
// queue. Downstream queriers must never see the end user's credentials: they
// act on behalf of the tenant that has already been authenticated by the
// frontend's HTTP auth middleware (X-Scope-OrgID is what carries the tenant
// identity between internal components). Leaking Authorization / Cookie values
// to queriers would hand them long-lived user credentials.
func stripCredentialHeaders(req *httpgrpc.HTTPRequest) {
	if req == nil {
		return
	}
	filtered := req.Headers[:0]
	for _, h := range req.Headers {
		switch strings.ToLower(h.Key) {
		case "authorization", "cookie", "proxy-authorization":
			// drop
		default:
			filtered = append(filtered, h)
		}
	}
	req.Headers = filtered
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
	req, err := server.HTTPRequest(r)
	if err != nil {
		return nil, err
	}

	// Do not forward end-user credential headers into the internal queue; the
	// querier runs with the tenant identity propagated via X-Scope-OrgID and
	// must not see the client's Authorization / Cookie values.
	stripCredentialHeaders(req)

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
