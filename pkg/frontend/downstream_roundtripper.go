package frontend

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/opentracing/opentracing-go"
	"github.com/weaveworks/common/httpgrpc"
)

// RoundTripper that forwards requests to downstream URL.
type downstreamRoundTripper struct {
	downstreamURL *url.URL
	transport     http.RoundTripper
}

func NewDownstreamRoundTripper(downstreamURL string, transport http.RoundTripper) (http.RoundTripper, error) {
	u, err := url.Parse(downstreamURL)
	if err != nil {
		return nil, err
	}

	return &downstreamRoundTripper{downstreamURL: u, transport: transport}, nil
}

// encodedDot is the percent-encoded form of a dot. It is split into pieces so
// the literal escape sequence does not appear verbatim in source.
const encodedDot = "%" + "2e"

func (d downstreamRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	tracer, span := opentracing.GlobalTracer(), opentracing.SpanFromContext(r.Context())
	if tracer != nil && span != nil {
		carrier := opentracing.HTTPHeadersCarrier(r.Header)
		err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier)
		if err != nil {
			return nil, err
		}
	}

	// Reject any request whose path is not already in canonical form. The
	// gorilla/mux router is configured with UseEncodedPath, so encoded dot
	// segments can reach this layer unchanged; resolving them later via
	// path.Clean would let a caller rewrite the proxied path.
	if cleaned := path.Clean(r.URL.Path); cleaned != r.URL.Path {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, "invalid path")
	}
	if escaped := strings.ToLower(r.URL.EscapedPath()); strings.Contains(escaped, encodedDot) {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, "invalid path")
	}

	// Operate on a clone of the request and its URL so callers (e.g. the
	// frontend handler's slow-query/stats logging) continue to see the
	// original path and Host after RoundTrip returns.
	outReq := r.Clone(r.Context())

	outReq.URL.Scheme = d.downstreamURL.Scheme
	outReq.URL.Host = d.downstreamURL.Host
	outReq.URL.Path = path.Join(d.downstreamURL.Path, outReq.URL.Path)
	// Clear RawPath so net/http re-encodes from the joined Path.
	outReq.URL.RawPath = ""
	outReq.Host = ""

	// Defence in depth: after joining, the outbound path must still start
	// with the configured downstream path prefix.
	if prefix := d.downstreamURL.Path; prefix != "" && prefix != "/" {
		trimmed := strings.TrimRight(prefix, "/")
		if trimmed != "" && outReq.URL.Path != trimmed && !strings.HasPrefix(outReq.URL.Path, trimmed+"/") {
			return nil, httpgrpc.Errorf(http.StatusBadRequest, "invalid path")
		}
	}

	return d.transport.RoundTrip(outReq)
}
