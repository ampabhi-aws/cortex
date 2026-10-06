package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/user"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestWriteError(t *testing.T) {
	for _, test := range []struct {
		status int
		err    error
	}{
		{http.StatusInternalServerError, errors.New("unknown")},
		{http.StatusGatewayTimeout, context.DeadlineExceeded},
		{StatusClientClosedRequest, context.Canceled},
		{http.StatusBadRequest, httpgrpc.Errorf(http.StatusBadRequest, "")},
	} {
		t.Run(test.err.Error(), func(t *testing.T) {
			w := httptest.NewRecorder()
			writeError(w, test.err)
			require.Equal(t, test.status, w.Result().StatusCode)
		})
	}
}

func TestHandler_ServeHTTP(t *testing.T) {
	for _, tt := range []struct {
		name            string
		cfg             HandlerConfig
		expectedMetrics int
	}{
		{
			name:            "test handler with stats enabled",
			cfg:             HandlerConfig{QueryStatsEnabled: true},
			expectedMetrics: 3,
		},
		{
			name:            "test handler with stats disabled",
			cfg:             HandlerConfig{QueryStatsEnabled: false},
			expectedMetrics: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			roundTripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{}")),
				}, nil
			})

			reg := prometheus.NewPedanticRegistry()
			handler := NewHandler(tt.cfg, roundTripper, log.NewNopLogger(), reg)

			ctx := user.InjectOrgID(context.Background(), "12345")
			req := httptest.NewRequest("GET", "/", nil)
			req = req.WithContext(ctx)
			resp := httptest.NewRecorder()

			handler.ServeHTTP(resp, req)
			_, _ = io.ReadAll(resp.Body)
			require.Equal(t, resp.Code, http.StatusOK)

			count, err := promtest.GatherAndCount(
				reg,
				"cortex_query_seconds_total",
				"cortex_query_fetched_series_total",
				"cortex_query_fetched_chunks_bytes_total",
			)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedMetrics, count)
		})
	}
}

func TestHandler_FiltersResponseHeadersAllowList(t *testing.T) {
	// A rogue/compromised upstream (querier) is simulated by returning a
	// response that contains both legitimate headers and attacker-controlled
	// headers. Only the allow-listed headers must reach the client.
	roundTripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-cache")
		h.Set("Results-Cache-Gen-Number", "42")
		h.Set("Set-Cookie", "session=attacker")
		h.Set("Location", "http://evil.example/")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("X-Totally-Made-Up", "nope")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("{}")),
		}, nil
	})

	reg := prometheus.NewPedanticRegistry()
	handler := NewHandler(HandlerConfig{}, roundTripper, log.NewNopLogger(), reg)

	ctx := user.InjectOrgID(context.Background(), "12345")
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(ctx)
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)
	_, _ = io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.Code)

	// Allowed headers must be present.
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", resp.Header().Get("Cache-Control"))
	assert.Equal(t, "42", resp.Header().Get("Results-Cache-Gen-Number"))

	// Attacker-controlled / unexpected headers must be stripped.
	assert.Empty(t, resp.Header().Get("Set-Cookie"))
	assert.Empty(t, resp.Header().Get("Location"))
	assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header().Get("X-Totally-Made-Up"))
}

func TestHandler_ExtraAllowedResponseHeaders(t *testing.T) {
	roundTripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("X-Custom-One", "a")
		h.Set("X-Custom-Two", "b")
		h.Set("X-Not-Allowed", "c")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("{}")),
		}, nil
	})

	reg := prometheus.NewPedanticRegistry()
	handler := NewHandler(HandlerConfig{ExtraAllowedRespHeaders: "X-Custom-One, x-custom-two"}, roundTripper, log.NewNopLogger(), reg)

	ctx := user.InjectOrgID(context.Background(), "12345")
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(ctx)
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)
	_, _ = io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.Code)

	assert.Equal(t, "a", resp.Header().Get("X-Custom-One"))
	assert.Equal(t, "b", resp.Header().Get("X-Custom-Two"))
	assert.Empty(t, resp.Header().Get("X-Not-Allowed"))
}
