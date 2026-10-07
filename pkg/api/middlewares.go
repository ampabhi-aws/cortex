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

// neverLogHeaders enumerates HTTP header names which must never have their
// contents written verbatim into a log line, because they commonly carry
// replayable credentials (bearer tokens, session cookies, API keys, STS
// tokens). Lookups must be performed against strings.ToLower(name).
var neverLogHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-amz-security-token": {},
	"x-api-key":            {},
}

// IsCredentialHeader reports whether the given HTTP header name is on the
// hard-coded denylist of credential-bearing headers whose values must never
// be logged verbatim.
func IsCredentialHeader(name string) bool {
	_, bad := neverLogHeaders[strings.ToLower(name)]
	return bad
}

// redactedHeaderValue is substituted for credential-bearing header values so
// that operators still see when such a header was present on a request
// (useful for troubleshooting) without the raw secret leaking into logs.
const redactedHeaderValue = "<redacted>"

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
		if IsCredentialHeader(target) {
			// Replace secret-bearing values with a static placeholder so
			// the header's presence is still visible in logs but the
			// credential never is.
			if r.Header.Get(target) != "" {
				headerMap[target] = redactedHeaderValue
			}
			continue
		}
		if contents := r.Header.Get(target); contents != "" {
			headerMap[target] = contents
		}
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
