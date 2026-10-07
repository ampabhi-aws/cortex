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

// inboundTracingHeaders enumerates request headers that carry trace propagation
// state and must not be trusted from external clients when the query-frontend
// forwards the request to internal gRPC components. Keys are compared
// case-insensitively.
var inboundTracingHeaders = map[string]struct{}{
	"uber-trace-id":  {},
	"traceparent":    {},
	"tracestate":     {},
	"jaeger-baggage": {},
}

// stripInboundTracingHeaders returns a copy of headers with any client-provided
// tracing propagation headers removed. Uber-baggage headers (prefixed
// "uberctx-" / "jaeger-ctx-") are also dropped.
func stripInboundTracingHeaders(headers []*httpgrpc.Header) []*httpgrpc.Header {
	if len(headers) == 0 {
		return headers
	}
	out := headers[:0]
	for _, h := range headers {
		if h == nil {
			continue
		}
		lower := strings.ToLower(h.Key)
		if _, ok := inboundTracingHeaders[lower]; ok {
			continue
		}
		if strings.HasPrefix(lower, "uberctx-") || strings.HasPrefix(lower, "jaeger-ctx-") {
			continue
		}
		out = append(out, h)
	}
	return out
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

	// Strip inbound client-controlled tracing headers before forwarding the request
	// over gRPC. These headers would otherwise be re-interpreted downstream (e.g. by
	// the scheduler, which extracts the parent span context from them) and a
	// malformed value can trigger error paths that previously crashed the
	// query-frontend. The frontend establishes its own trace context, so client
	// propagation values are not trusted.
	req.Headers = stripInboundTracingHeaders(req.Headers)

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
