package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/purger"
	"github.com/cortexproject/cortex/pkg/querier/tripperware/queryrange"
	"github.com/cortexproject/cortex/pkg/tenant"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// defaultMaxProfilingSeconds is the default upper bound (in seconds) applied to
// the attacker-controlled `seconds` query parameter accepted by profiling
// endpoints such as /debug/fgprof. The vendored fgprof handler itself only
// rejects non-positive values, which allows an unauthenticated caller to pin
// the process into a continuous 99 Hz stop-the-world sampler. Capping the
// value here and limiting concurrency defends every Cortex component against
// that DoS even when the operator has not (yet) placed authentication in
// front of the HTTP listener. See
// https://github.com/cortexproject/cortex/security.
const defaultMaxProfilingSeconds = 30

// profilingSem serialises profiling sessions to a single in-flight request per
// process. Multiple concurrent fgprof sessions each spawn their own 99 Hz
// stop-the-world sampler goroutine (runtime.GoroutineProfile), so N concurrent
// sessions multiply the STW overhead by N; serialising them bounds the
// worst-case impact to a single profile at a time.
var profilingSem = make(chan struct{}, 1)

// boundedProfilingHandler wraps a profiling handler (fgprof or net/http/pprof
// `profile`) with three defences against the unbounded-duration DoS described
// in Cortex security advisories:
//
//  1. `seconds` is validated against maxSeconds (0 < n <= maxSeconds); callers
//     that omit `seconds` fall through to the vendored handler's default.
//  2. At most one profiling session runs at a time; concurrent requests get
//     HTTP 429 (TooManyRequests) instead of each spinning up their own
//     stop-the-world sampler.
//  3. The handler is wrapped in http.TimeoutHandler so that the goroutine is
//     unblocked once the (bounded) deadline elapses even when the vendored
//     fgprof handler fails to consult r.Context() on client disconnect.
func boundedProfilingHandler(inner http.Handler, maxSeconds int) http.Handler {
	if maxSeconds <= 0 {
		maxSeconds = defaultMaxProfilingSeconds
	}
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := r.URL.Query().Get("seconds"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 || n > maxSeconds {
				http.Error(w, "seconds out of range", http.StatusBadRequest)
				return
			}
		}
		select {
		case profilingSem <- struct{}{}:
			defer func() { <-profilingSem }()
		default:
			http.Error(w, "profiling already in progress", http.StatusTooManyRequests)
			return
		}
		inner.ServeHTTP(w, r)
	})
	// Give the handler slightly more than maxSeconds so a legitimate profile
	// at the cap still completes before the TimeoutHandler kicks in, but a
	// bug-for-bug client that ignores r.Context() cannot run forever.
	timeout := time.Duration(maxSeconds+5) * time.Second
	return http.TimeoutHandler(gate, timeout, "profiling deadline exceeded")
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
