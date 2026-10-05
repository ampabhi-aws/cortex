package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/purger"
	"github.com/cortexproject/cortex/pkg/querier/tripperware/queryrange"
	"github.com/cortexproject/cortex/pkg/tenant"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// sensitiveRequestHeaderDenyList is defined in pkg/util/log so it can also be
// enforced by the log wrappers and the HTTP/gRPC propagation helpers (which
// cannot import pkg/api). See util_log.IsSensitiveRequestHeader.

// IsSensitiveRequestHeader reports whether the given HTTP header name is on
// the credential-header deny-list and must not be captured for logging or
// propagation. It is a thin forwarder to util_log.IsSensitiveRequestHeader
// kept here for API-package call sites and tests.
func IsSensitiveRequestHeader(name string) bool {
	return util_log.IsSensitiveRequestHeader(name)
}

// NewHTTPHeaderMiddleware constructs an HTTPHeaderMiddleware after dropping any
// operator-configured header name that is on the credential-header deny-list.
// It logs a warning naming each rejected header so the operator is made aware
// that their configuration was partially ignored for safety. If every
// configured header is rejected (or the list was empty) it returns nil so
// callers can skip registering the middleware entirely.
func NewHTTPHeaderMiddleware(targetHeaders []string, logger log.Logger) *HTTPHeaderMiddleware {
	safe, rejected := util_log.FilterSensitiveHeaderNames(targetHeaders)
	if len(rejected) > 0 && logger != nil {
		level.Warn(logger).Log(
			"msg", "ignoring credential-bearing HTTP header names configured via -api.http-request-headers-to-log; "+
				"logging these would leak end-user credentials into service logs and propagate them to downstream components",
			"rejected_headers", strings.Join(rejected, ","),
		)
	}
	if len(safe) == 0 {
		return nil
	}
	return &HTTPHeaderMiddleware{TargetHeaders: safe}
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
		// Defense in depth: never capture credential-bearing headers even if
		// one slipped past construction-time filtering (e.g. a target list
		// mutated after NewHTTPHeaderMiddleware was called, or a direct
		// struct-literal construction in a test).
		if IsSensitiveRequestHeader(target) {
			continue
		}
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
