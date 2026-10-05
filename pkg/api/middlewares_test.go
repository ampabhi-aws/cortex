package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-kit/log"
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

// TestSensitiveHeadersAreNeverCaptured verifies that credential-bearing
// request headers (Authorization, Cookie, etc.) are never recorded on the
// request context even if an operator explicitly listed them in
// -api.http-request-headers-to-log. This is the core defense for
// CWE-532: Insertion of Sensitive Information into Log File.
func TestSensitiveHeadersAreNeverCaptured(t *testing.T) {
	sensitive := []string{
		"Authorization",
		"authorization", // case-insensitive
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		"X-Amz-Security-Token",
		"X-Api-Key",
		"X-Auth-Token",
		"X-Csrf-Token",
		"X-Xsrf-Token",
		"X-Vault-Token",
	}

	for _, name := range sensitive {
		require.Truef(t, IsSensitiveRequestHeader(name), "%q should be on the deny-list", name)
	}

	// Even if an attacker/operator forces a direct struct-literal construction
	// that bypasses NewHTTPHeaderMiddleware, the capture loop itself must
	// still refuse to record the sensitive values.
	h := http.Header{}
	h.Set("Authorization", "Bearer super-secret-token")
	h.Set("Cookie", "session=super-secret-session")
	h.Set("X-Request-ID", "safe-value")

	req := (&http.Request{
		Method:     "GET",
		RequestURI: "/push",
		Body:       http.NoBody,
		Header:     h,
	}).WithContext(context.Background())

	mw := HTTPHeaderMiddleware{TargetHeaders: []string{"Authorization", "Cookie", "X-Request-ID"}}
	ctx := mw.InjectTargetHeadersIntoHTTPRequest(req)

	got := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, got)
	require.NotContains(t, got, "Authorization")
	require.NotContains(t, got, "Cookie")
	require.Equal(t, "safe-value", got["X-Request-ID"])
}

// TestNewHTTPHeaderMiddlewareRejectsCredentialHeaders verifies the
// construction-time filter: credential-bearing names are dropped from the
// operator-supplied list, and if every name is a credential header the
// middleware is not created at all.
func TestNewHTTPHeaderMiddlewareRejectsCredentialHeaders(t *testing.T) {
	mw := NewHTTPHeaderMiddleware([]string{"Authorization", "X-Request-ID", "Cookie"}, log.NewNopLogger())
	require.NotNil(t, mw)
	require.Equal(t, []string{"X-Request-ID"}, mw.TargetHeaders)

	// If every configured header is a credential header, no middleware is
	// returned so the request pipeline skips header capture entirely.
	require.Nil(t, NewHTTPHeaderMiddleware([]string{"Authorization", "Cookie"}, log.NewNopLogger()))
	require.Nil(t, NewHTTPHeaderMiddleware(nil, log.NewNopLogger()))
}
