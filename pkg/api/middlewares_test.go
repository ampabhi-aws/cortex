package api

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestDenyAllAdminMiddleware_ReturnsForbidden(t *testing.T) {
	mw := denyAllAdminMiddleware(nil)

	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		reached = true
	})

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, reached, "deny-all middleware must not call next")
}

func TestPassthroughAdminMiddleware_ForwardsRequest(t *testing.T) {
	mw := passthroughAdminMiddleware()

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rec, req)

	require.True(t, reached, "passthrough middleware must forward to next")
	require.Equal(t, http.StatusTeapot, rec.Code)
}
