package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
)

type captureRoundTripper struct {
	req *httpgrpc.HTTPRequest
}

func (c *captureRoundTripper) RoundTripGRPC(_ context.Context, req *httpgrpc.HTTPRequest) (*httpgrpc.HTTPResponse, error) {
	c.req = req
	return &httpgrpc.HTTPResponse{Code: 200}, nil
}

// TestGrpcRoundTripperStripsSensitiveHeaders verifies that credentials present
// on an inbound HTTP request are not forwarded to the gRPC querier, so that a
// (potentially rogue or compromised) querier worker never observes the tenant's
// Authorization / Cookie / Proxy-Authorization header values.
func TestGrpcRoundTripperStripsSensitiveHeaders(t *testing.T) {
	capture := &captureRoundTripper{}
	rt := AdaptGrpcRoundTripperToHTTPRoundTripper(capture)

	r := httptest.NewRequest(http.MethodGet, "http://example/prometheus/api/v1/query?query=up", nil)
	r.Header.Set("Authorization", "Bearer victim-secret")
	r.Header.Set("Cookie", "session=secret")
	r.Header.Set("Proxy-Authorization", "Basic cHJveHk6Y3JlZHM=")
	r.Header.Set("X-Scope-OrgID", "victim")
	r.Header.Set("User-Agent", "test")
	originalAuth := r.Header.Get("Authorization")

	_, err := rt.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, capture.req)

	seen := map[string][]string{}
	for _, h := range capture.req.Headers {
		seen[http.CanonicalHeaderKey(h.Key)] = h.Values
	}
	for _, forbidden := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		_, ok := seen[forbidden]
		assert.Falsef(t, ok, "sensitive header %q must not be forwarded to the querier (saw %v)", forbidden, seen[forbidden])
	}
	// Non-sensitive headers must still be forwarded.
	assert.Equal(t, []string{"victim"}, seen["X-Scope-Orgid"], "tenant header must be preserved; headers=%v", seen)
	assert.Equal(t, []string{"test"}, seen["User-Agent"])

	// The caller's http.Request header map must not have been mutated.
	assert.Equal(t, originalAuth, r.Header.Get("Authorization"),
		"caller-supplied request headers must not be mutated in place")
}

// TestGrpcRoundTripperPreservesNonSensitiveHeaders exercises the common path
// where there is nothing to strip: no sensitive header appears downstream and
// the tenant header is still propagated.
func TestGrpcRoundTripperPreservesNonSensitiveHeaders(t *testing.T) {
	capture := &captureRoundTripper{}
	rt := AdaptGrpcRoundTripperToHTTPRoundTripper(capture)

	r := httptest.NewRequest(http.MethodGet, "http://example/prometheus/api/v1/query?query=up", nil)
	r.Header.Set("X-Scope-OrgID", "tenant-1")

	_, err := rt.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, capture.req)

	sawTenant := false
	for _, h := range capture.req.Headers {
		switch strings.ToLower(h.Key) {
		case "authorization", "cookie", "proxy-authorization":
			t.Fatalf("unexpected sensitive header %q leaked downstream", h.Key)
		case "x-scope-orgid":
			sawTenant = true
			assert.Equal(t, []string{"tenant-1"}, h.Values)
		}
	}
	assert.True(t, sawTenant, "tenant header must still be forwarded to the querier")
}
