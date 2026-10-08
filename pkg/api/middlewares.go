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

// sensitiveHeaders is a denylist of well-known credential-bearing HTTP header
// names. Values of headers whose canonical (lower-case) name is in this set
// must never be captured for request-tracing logs or propagated across
// components, because doing so persists end-user credentials in plaintext.
//
// The map is keyed by lower-case header name; callers lower-case before
// lookup.
var sensitiveHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-api-key":            {},
	"x-auth-token":         {},
	"x-amz-security-token": {},
}

// maxLoggedHeaderLen caps the number of bytes of any single captured header
// value that will be stored for logging. Values longer than this are
// truncated with an ellipsis so that anonymous callers cannot inject
// unbounded log fields and amplify log volume.
const maxLoggedHeaderLen = 256

// IsSensitiveHeader reports whether the given header name is in the
// built-in credential-header denylist. The comparison is case-insensitive.
func IsSensitiveHeader(name string) bool {
	_, bad := sensitiveHeaders[strings.ToLower(name)]
	return bad
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

// InjectTargetHeadersIntoHTTPRequest injects specified HTTPHeaders into the
// request context.
//
// Headers whose name matches the built-in credential-header denylist
// (sensitiveHeaders) are never captured, regardless of operator
// configuration, so that bearer tokens, cookies and API keys cannot be
// persisted into plaintext logs or propagated to other components. Captured
// values are also truncated to maxLoggedHeaderLen bytes to bound the size of
// attacker-controlled log fields.
func (h HTTPHeaderMiddleware) InjectTargetHeadersIntoHTTPRequest(r *http.Request) context.Context {
	headerMap := make(map[string]string)

	// Check to make sure that Headers have not already been injected
	checkMapInContext := util_log.HeaderMapFromContext(r.Context())
	if checkMapInContext != nil {
		return r.Context()
	}

	for _, target := range h.TargetHeaders {
		if IsSensitiveHeader(target) {
			// Never capture credential-bearing headers.
			continue
		}
		contents := r.Header.Get(target)
		if contents == "" {
			continue
		}
		if len(contents) > maxLoggedHeaderLen {
			contents = contents[:maxLoggedHeaderLen] + "…"
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
