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

// HTTPHeaderMiddleware adds specified HTTPHeaders to the request context
type HTTPHeaderMiddleware struct {
	TargetHeaders []string
}

// InjectTargetHeadersIntoHTTPRequest injects specified HTTPHeaders into the
// request context. The map is always re-derived from h.TargetHeaders at this
// trust boundary — a map pre-existing in the context (for example one that
// originated from gRPC metadata via HTTPHeaderPropagationServerInterceptor on
// an httpgrpc.HTTP/Handle call) is NOT trusted verbatim. Entries from an
// existing context map are merged only if their key is on the operator
// allowlist, so de-duplication still works but caller-controlled keys cannot
// bypass the allowlist.
func (h HTTPHeaderMiddleware) InjectTargetHeadersIntoHTTPRequest(r *http.Request) context.Context {
	headerMap := make(map[string]string)

	// Build a case-insensitive allowlist index.
	allow := make(map[string]string, len(h.TargetHeaders))
	for _, target := range h.TargetHeaders {
		allow[strings.ToLower(target)] = target
	}

	// Start from any map already in the context, but keep only allowlisted
	// keys. This re-applies the operator allowlist at every trust boundary.
	if existing := util_log.HeaderMapFromContext(r.Context()); existing != nil {
		for k, v := range existing {
			if canonical, ok := allow[strings.ToLower(k)]; ok {
				headerMap[canonical] = v
			}
		}
	}

	// Prefer values from the actual HTTP request headers when present —
	// these have passed through the HTTP server's standard header parsing.
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
