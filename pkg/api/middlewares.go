package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/purger"
	"github.com/cortexproject/cortex/pkg/querier/tripperware/queryrange"
	"github.com/cortexproject/cortex/pkg/tenant"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// maxLoggedHeaderLen caps the number of bytes of a header value that will be
// propagated through the logging header context. This prevents a single large
// request header from inflating every log line (and gRPC metadata forwarding)
// for a request.
const maxLoggedHeaderLen = 1024

// DeniedLogHeaders is the set of HTTP request header names that must never be
// stored in the logging header context, even if the operator asks for them via
// -api.http-request-headers-to-log. These headers carry credentials or other
// bearer secrets whose exposure in component logs would be a disclosure of
// tenant/user secrets. Comparison is case-insensitive.
var DeniedLogHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-amz-security-token": {},
	"x-api-key":            {},
	"x-auth-token":         {},
}

// IsDeniedLogHeader reports whether the given header name is on the credential
// denylist and therefore must not be logged.
func IsDeniedLogHeader(name string) bool {
	_, denied := DeniedLogHeaders[strings.ToLower(strings.TrimSpace(name))]
	return denied
}

// middleware for setting cache gen header to let consumer of response know all previous responses could be invalid due to delete operation
func getHTTPCacheGenNumberHeaderSetterMiddleware(cacheGenNumbersLoader purger.TombstonesLoader) middleware.Interface {
	return middleware.Func(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantIDs, err := tenant.TenantIDs(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			cacheGenNumber := cacheGenNumbersLoader.GetResultsCacheGenNumber(tenantIDs)

			w.Header().Set(queryrange.ResultsCacheGenNumberHeaderName, cacheGenNumber)
			next.ServeHTTP(w, r)
		})
	})
}

// HTTPHeaderMiddleware adds specified HTTPHeaders to the request context
type HTTPHeaderMiddleware struct {
	TargetHeaders []string
}

// InjectTargetHeadersIntoHTTPRequest injects specified HTTPHeaders into the request context
func (h HTTPHeaderMiddleware) InjectTargetHeadersIntoHTTPRequest(r *http.Request) context.Context {
	headerMap := make(map[string]string)

	// Check to make sure that Headers have not already been injected
	checkMapInContext := util_log.HeaderMapFromContext(r.Context())
	if checkMapInContext != nil {
		return r.Context()
	}

	for _, target := range h.TargetHeaders {
		// Never log credential-bearing headers, even if an operator asks for
		// them explicitly. Config.Validate rejects these at startup but we
		// also enforce it here as defence-in-depth in case a middleware is
		// constructed directly.
		if IsDeniedLogHeader(target) {
			continue
		}
		contents := r.Header.Get(target)
		if contents == "" {
			continue
		}
		if len(contents) > maxLoggedHeaderLen {
			contents = contents[:maxLoggedHeaderLen]
		}
		headerMap[target] = contents
	}
	return util_log.ContextWithHeaderMap(r.Context(), headerMap)
}

// Wrap implements Middleware
func (h HTTPHeaderMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := h.InjectTargetHeadersIntoHTTPRequest(r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
