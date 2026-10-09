package api

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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
		contents := r.Header.Get(target)
		if contents != "" {
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

// denyAllAdminMiddleware returns a middleware that short-circuits every
// request with HTTP 403. It is used as the fail-closed default for
// administrative endpoints (/config, /runtime_config) when the operator
// has not injected a real admin credential check (mTLS, bearer token or
// allowlisted admin identity).
func denyAllAdminMiddleware(logger log.Logger) middleware.Interface {
	return middleware.Func(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if logger != nil {
				level.Warn(logger).Log(
					"msg", "denying request to admin endpoint: no HTTPAdminMiddleware configured",
					"path", r.URL.Path,
					"remote", r.RemoteAddr,
				)
			}
			http.Error(w, "forbidden: administrative endpoint requires an admin credential check; configure HTTPAdminMiddleware or set -api.admin-endpoints-require-auth=false (not recommended)", http.StatusForbidden)
		})
	})
}

// passthroughAdminMiddleware is the opt-out middleware for operators that
// disable admin-endpoint authorization because the HTTP listener is isolated
// by other means (for example a dedicated admin network).
func passthroughAdminMiddleware() middleware.Interface {
	return middleware.Func(func(next http.Handler) http.Handler {
		return next
	})
}
