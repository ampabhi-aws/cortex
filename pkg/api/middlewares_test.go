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

func TestCredentialHeadersAreNotLogged(t *testing.T) {
	mw := HTTPHeaderMiddleware{TargetHeaders: []string{
		"Authorization",
		"authorization",
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		"X-Amz-Security-Token",
		"X-Api-Key",
		"X-Auth-Token",
		"X-Request-ID",
	}}

	h := http.Header{}
	h.Add("Authorization", "Bearer SECRET")
	h.Add("Proxy-Authorization", "Basic SECRET")
	h.Add("Cookie", "session=SECRET")
	h.Add("Set-Cookie", "a=b")
	h.Add("X-Amz-Security-Token", "SECRET")
	h.Add("X-Api-Key", "SECRET")
	h.Add("X-Auth-Token", "SECRET")
	h.Add("X-Request-ID", "abc123")

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}
	req = req.WithContext(context.Background())
	ctx := mw.InjectTargetHeadersIntoHTTPRequest(req)

	headerMap := util_log.HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)

	require.NotContains(t, headerMap, "Authorization")
	require.NotContains(t, headerMap, "authorization")
	require.NotContains(t, headerMap, "Proxy-Authorization")
	require.NotContains(t, headerMap, "Cookie")
	require.NotContains(t, headerMap, "Set-Cookie")
	require.NotContains(t, headerMap, "X-Amz-Security-Token")
	require.NotContains(t, headerMap, "X-Api-Key")
	require.NotContains(t, headerMap, "X-Auth-Token")
	require.Equal(t, "abc123", headerMap["X-Request-ID"])
}

func TestLongHeaderValuesAreTruncated(t *testing.T) {
	mw := HTTPHeaderMiddleware{TargetHeaders: []string{"X-Request-ID"}}

	long := strings.Repeat("a", maxLoggedHeaderLen+100)
	h := http.Header{}
	h.Add("X-Request-ID", long)

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}
	req = req.WithContext(context.Background())
	ctx := mw.InjectTargetHeadersIntoHTTPRequest(req)

	headerMap := util_log.HeaderMapFromContext(ctx)
	require.Equal(t, maxLoggedHeaderLen, len(headerMap["X-Request-ID"]))
}

func TestConfigValidateRejectsCredentialHeaders(t *testing.T) {
	cfg := Config{HTTPRequestHeadersToLog: []string{"X-Request-ID", "Authorization"}}
	err := cfg.Validate()
	require.Error(t, err)

	cfg = Config{HTTPRequestHeadersToLog: []string{"X-Request-ID"}}
	require.NoError(t, cfg.Validate())

	cfg = Config{HTTPRequestHeadersToLog: []string{"cookie"}}
	require.Error(t, cfg.Validate())
}
