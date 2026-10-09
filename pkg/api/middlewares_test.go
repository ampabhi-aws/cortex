package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

var HTTPTestMiddleware = HTTPHeaderMiddleware{TargetHeaders: []string{"TestHeader1", "TestHeader2", "Test3"}}

func TestHeaderInjection(t *testing.T) {
	ctx := context.Background()
	h := http.Header{}
	contentsMap := make(map[string]string)
	contentsMap["TestHeader1"] = "RequestID"
	contentsMap["TestHeader2"] = "ContentsOfTestHeader2"
	contentsMap["Test3"] = "SomeInformation"

	h.Add("TestHeader1", contentsMap["TestHeader1"])
	h.Add("TestHeader2", contentsMap["TestHeader2"])
	h.Add("Test3", contentsMap["Test3"])

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}

	req = req.WithContext(ctx)
	ctx = HTTPTestMiddleware.InjectTargetHeadersIntoHTTPRequest(req)

	headerMap := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)

	for _, header := range HTTPTestMiddleware.TargetHeaders {
		require.Equal(t, contentsMap[header], headerMap[header])
	}
	for header, contents := range contentsMap {
		require.Equal(t, contents, headerMap[header])
	}
}

// TestAllowlistedExistingHeaderInContextIsPreserved verifies that an existing
// map in the context is merged into the fresh map but only for allowlisted
// keys. This covers the de-duplication / forwarding path.
func TestAllowlistedExistingHeaderInContextIsPreserved(t *testing.T) {
	ctx := context.Background()

	existing := map[string]string{
		"TestHeader1": "FromCtx1",
		"TestHeader2": "FromCtx2",
		"Test3":       "FromCtx3",
	}
	ctx = util_log.ContextWithHeaderMap(ctx, existing)

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     http.Header{},
	}
	req = req.WithContext(ctx)
	ctx = HTTPTestMiddleware.InjectTargetHeadersIntoHTTPRequest(req)

	got := util_log.HeaderMapFromContext(ctx)
	require.Equal(t, existing, got)
}

// TestNonAllowlistedExistingHeaderInContextIsDropped verifies the fix: a map
// pre-populated in the context (e.g. by a hostile gRPC caller via the
// HTTPHeaderPropagationServerInterceptor on httpgrpc.HTTP/Handle) does NOT
// bypass the operator allowlist. Only allowlisted keys survive, so attacker-
// controlled keys cannot become log fields or be injected as HTTP headers.
func TestNonAllowlistedExistingHeaderInContextIsDropped(t *testing.T) {
	ctx := context.Background()

	hostile := map[string]string{
		"TestHeader1":   "legit",
		"attacker_key":  "attacker_value",
		"=":             "x", // would cause logfmt to drop the whole record
		"X-Injected":    "1", // would be injected into downstream HTTP requests
	}
	ctx = util_log.ContextWithHeaderMap(ctx, hostile)

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     http.Header{},
	}
	req = req.WithContext(ctx)
	ctx = HTTPTestMiddleware.InjectTargetHeadersIntoHTTPRequest(req)

	got := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, got)
	require.Equal(t, map[string]string{"TestHeader1": "legit"}, got)
}

// TestRequestHeadersOverrideContext verifies that values from the real HTTP
// request headers take precedence over values coming from the context map, so
// httpgrpc callers cannot use the context to override headers set by the HTTP
// layer.
func TestRequestHeadersOverrideContext(t *testing.T) {
	ctx := util_log.ContextWithHeaderMap(context.Background(), map[string]string{
		"TestHeader1": "from-ctx",
	})

	h := http.Header{}
	h.Add("TestHeader1", "from-request")

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}
	req = req.WithContext(ctx)
	ctx = HTTPTestMiddleware.InjectTargetHeadersIntoHTTPRequest(req)

	got := util_log.HeaderMapFromContext(ctx)
	require.Equal(t, "from-request", got["TestHeader1"])
}
