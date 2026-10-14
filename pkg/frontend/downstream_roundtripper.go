package frontend

import (
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/opentracing/opentracing-go"
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

func (d downstreamRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	tracer, span := opentracing.GlobalTracer(), opentracing.SpanFromContext(r.Context())
	if tracer != nil && span != nil {
		carrier := opentracing.HTTPHeadersCarrier(r.Header)
		err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier)
		if err != nil {
			return nil, err
		}
	}

	r.URL.Scheme = d.downstreamURL.Scheme
	r.URL.Host = d.downstreamURL.Host
	r.URL.Path = path.Join(d.downstreamURL.Path, r.URL.Path)
	r.Host = ""
	resp, err := d.transport.RoundTrip(r)
	if err != nil {
		// Strip the URL from any *url.Error returned by the transport.
		// The URL embeds the operator's internal downstream scheme, host,
		// port, path and (via the wrapped net.OpError) the dialed IP, none
		// of which should ever reach tenants if this error is logged or
		// serialised. Keep the operation and underlying error so operators
		// still get useful detail in server-side logs.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return nil, &url.Error{Op: uerr.Op, URL: "", Err: uerr.Err}
		}
		return nil, err
	}
	return resp, nil
}
