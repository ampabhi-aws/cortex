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

func TestExistingHeaderInContextIsOverriddenByAllowlist(t *testing.T) {
	ctx := context.Background()

	h := http.Header{}
	preexisting := map[string]string{
		"TestHeader1": "ShouldBeDroppedBecauseGRPCProvided",
		"InjectedKey": "ShouldBeDropped",
		"org_id":      "spoofed",
	}

	h.Add("TestHeader1", "FromHTTP1")
	h.Add("TestHeader2", "FromHTTP2")
	h.Add("Test3", "FromHTTP3")

	ctx = util_log.ContextWithHeaderMap(ctx, preexisting)
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
	// The map must be fully re-derived from the allowlist and the actual
	// HTTP request headers; the previously-injected (potentially
	// gRPC-supplied) map must not survive.
	require.Equal(t, map[string]string{
		"TestHeader1": "FromHTTP1",
		"TestHeader2": "FromHTTP2",
		"Test3":       "FromHTTP3",
	}, headerMap)
}
