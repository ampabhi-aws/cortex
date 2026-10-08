package api

import (
	"context"
	"net/http"
	"strings"
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

func TestExistingHeaderInContextIsNotOverridden(t *testing.T) {
	ctx := context.Background()

	h := http.Header{}
	contentsMap := make(map[string]string)
	contentsMap["TestHeader1"] = "RequestID"
	contentsMap["TestHeader2"] = "ContentsOfTestHeader2"
	contentsMap["Test3"] = "SomeInformation"

	h.Add("TestHeader1", "Fail1")
	h.Add("TestHeader2", "Fail2")
	h.Add("Test3", "Fail3")

	ctx = util_log.ContextWithHeaderMap(ctx, contentsMap)
	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}

	req = req.WithContext(ctx)
	ctx = HTTPTestMiddleware.InjectTargetHeadersIntoHTTPRequest(req)

	require.Equal(t, contentsMap, util_log.HeaderMapFromContext(ctx))

}

func TestSensitiveHeadersAreNotCaptured(t *testing.T) {
	mw := HTTPHeaderMiddleware{TargetHeaders: []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Api-Key", "X-Auth-Token", "X-Amz-Security-Token",
		"X-Request-ID",
	}}

	h := http.Header{}
	h.Set("Authorization", "Bearer SUPER-SECRET-TOKEN")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Cookie", "session=abc")
	h.Set("Set-Cookie", "session=abc")
	h.Set("X-Api-Key", "key")
	h.Set("X-Auth-Token", "tok")
	h.Set("X-Amz-Security-Token", "stok")
	h.Set("X-Request-ID", "req-1")

	req := (&http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}).WithContext(context.Background())

	ctx := mw.InjectTargetHeadersIntoHTTPRequest(req)
	headerMap := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)

	// Credential-bearing headers must not be captured at all, regardless of
	// how the operator spelled their name in -api.http-request-headers-to-log.
	for _, bad := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Api-Key", "X-Auth-Token", "X-Amz-Security-Token",
	} {
		_, present := headerMap[bad]
		require.Falsef(t, present, "sensitive header %q must not be captured", bad)
	}

	// Non-sensitive headers continue to flow through unchanged.
	require.Equal(t, "req-1", headerMap["X-Request-ID"])
}

func TestCapturedHeaderValuesAreTruncated(t *testing.T) {
	mw := HTTPHeaderMiddleware{TargetHeaders: []string{"X-Request-ID"}}

	long := strings.Repeat("A", maxLoggedHeaderLen+100)
	h := http.Header{}
	h.Set("X-Request-ID", long)

	req := (&http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}).WithContext(context.Background())

	ctx := mw.InjectTargetHeadersIntoHTTPRequest(req)
	headerMap := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)

	got := headerMap["X-Request-ID"]
	require.NotEqual(t, long, got, "long header value must be truncated")
	require.True(t, strings.HasPrefix(got, strings.Repeat("A", maxLoggedHeaderLen)))
	require.True(t, strings.HasSuffix(got, "\u2026"))
}

func TestIsSensitiveHeader(t *testing.T) {
	for _, name := range []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Api-Key", "x-api-key",
		"X-Auth-Token", "X-Amz-Security-Token",
	} {
		require.Truef(t, IsSensitiveHeader(name), "%q should be sensitive", name)
	}
	for _, name := range []string{
		"X-Scope-OrgID", "X-Request-ID", "X-Forwarded-For", "",
	} {
		require.Falsef(t, IsSensitiveHeader(name), "%q should NOT be sensitive", name)
	}
}
