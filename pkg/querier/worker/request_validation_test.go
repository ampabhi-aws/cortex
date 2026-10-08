package worker

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/common/httpgrpc"
)

func TestValidateAndSanitizeWorkerRequest(t *testing.T) {
	prefixes := []string{"/prometheus/api/v1/", "/api/prom/api/v1/", "/api/v1/"}

	tests := []struct {
		name     string
		req      *httpgrpc.HTTPRequest
		prefixes []string
		wantCode int32
	}{
		{
			name:     "nil request rejected",
			req:      nil,
			prefixes: prefixes,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "empty prefixes rejects everything",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/prometheus/api/v1/query?query=up"},
			prefixes: nil,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "disallowed method",
			req:      &httpgrpc.HTTPRequest{Method: "DELETE", Url: "/api/v1/series"},
			prefixes: prefixes,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "disallowed admin path /config",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/config"},
			prefixes: prefixes,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "disallowed admin path /debug/pprof/heap",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/debug/pprof/heap"},
			prefixes: prefixes,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "disallowed POST /ingester/ring",
			req:      &httpgrpc.HTTPRequest{Method: "POST", Url: "/ingester/ring", Body: []byte("forget=foo")},
			prefixes: prefixes,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "invalid URL rejected",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "not a url"},
			prefixes: prefixes,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "allowed Prometheus API GET",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/prometheus/api/v1/query?query=up"},
			prefixes: prefixes,
			wantCode: 0,
		},
		{
			name:     "allowed legacy API POST",
			req:      &httpgrpc.HTTPRequest{Method: "POST", Url: "/api/prom/api/v1/query_range"},
			prefixes: prefixes,
			wantCode: 0,
		},
		{
			name:     "prefix must be exact (no /prometheus-admin bypass)",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/prometheus-admin/api/v1/query?query=up"},
			prefixes: prefixes,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "query string cannot smuggle allowed prefix",
			req:      &httpgrpc.HTTPRequest{Method: "GET", Url: "/config?x=/api/v1/query"},
			prefixes: prefixes,
			wantCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := validateAndSanitizeWorkerRequest(tc.req, tc.prefixes)
			if tc.wantCode == 0 {
				assert.Nil(t, resp, "expected request to be accepted")
			} else {
				if assert.NotNil(t, resp, "expected request to be rejected") {
					assert.Equal(t, tc.wantCode, resp.Code)
				}
			}
		})
	}
}

func TestValidateAndSanitizeWorkerRequest_StripsHeaders(t *testing.T) {
	req := &httpgrpc.HTTPRequest{
		Method: "GET",
		Url:    "/api/v1/query?query=up",
		Headers: []*httpgrpc.Header{
			{Key: "X-Scope-OrgID", Values: []string{"tenant-1"}},
			{Key: "Content-Type", Values: []string{"application/json"}},
			{Key: "Connection", Values: []string{"close"}},
			{Key: "Transfer-Encoding", Values: []string{"chunked"}},
			{Key: "X-Forwarded-For", Values: []string{"1.2.3.4"}},
			{Key: "X-Real-IP", Values: []string{"5.6.7.8"}},
			{Key: "Forwarded", Values: []string{"for=1.2.3.4"}},
			{Key: "User-Agent", Values: []string{"ua"}},
		},
	}

	resp := validateAndSanitizeWorkerRequest(req, []string{"/api/v1/"})
	assert.Nil(t, resp)

	keys := map[string]bool{}
	for _, h := range req.Headers {
		keys[h.Key] = true
	}
	// Preserved
	assert.True(t, keys["X-Scope-OrgID"], "X-Scope-OrgID should be preserved for tenant routing")
	assert.True(t, keys["Content-Type"])
	assert.True(t, keys["User-Agent"])
	// Stripped
	assert.False(t, keys["Connection"], "hop-by-hop should be stripped")
	assert.False(t, keys["Transfer-Encoding"], "hop-by-hop should be stripped")
	assert.False(t, keys["X-Forwarded-For"], "spoofable source header should be stripped")
	assert.False(t, keys["X-Real-IP"])
	assert.False(t, keys["Forwarded"])
}
