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

func TestCredentialHeadersAreRedacted(t *testing.T) {
	ctx := context.Background()

	mw := HTTPHeaderMiddleware{TargetHeaders: []string{"Authorization", "Cookie", "X-Request-ID"}}

	h := http.Header{}
	h.Add("Authorization", "Bearer SUPER-SECRET")
	h.Add("Cookie", "session=abc")
	h.Add("X-Request-ID", "req-123")

	req := (&http.Request{
		Method:     "GET",
		RequestURI: "/",
		Body:       http.NoBody,
		Header:     h,
	}).WithContext(ctx)

	ctx = mw.InjectTargetHeadersIntoHTTPRequest(req)
	hm := util_log.HeaderMapFromContext(ctx)

	require.Equal(t, "<redacted>", hm["Authorization"])
	require.Equal(t, "<redacted>", hm["Cookie"])
	require.Equal(t, "req-123", hm["X-Request-ID"])
}

func TestIsCredentialHeader(t *testing.T) {
	require.True(t, IsCredentialHeader("Authorization"))
	require.True(t, IsCredentialHeader("authorization"))
	require.True(t, IsCredentialHeader("Cookie"))
	require.True(t, IsCredentialHeader("Set-Cookie"))
	require.True(t, IsCredentialHeader("X-Api-Key"))
	require.True(t, IsCredentialHeader("x-amz-security-token"))
	require.True(t, IsCredentialHeader("Proxy-Authorization"))
	require.False(t, IsCredentialHeader("X-Request-ID"))
	require.False(t, IsCredentialHeader(""))
}
