package api

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/felixge/fgprof"
)

// Guardrails applied to the vendored fgprof handler when exposed on the
// shared HTTP listener. The upstream handler accepts an unbounded seconds
// query parameter and runs a 99 Hz runtime.GoroutineProfile sampler for the
// requested duration without any concurrency guard, so without these limits a
// single request can pin a stop-the-world profiler on the shared process
// effectively forever. See CWE-410.
const (
	// fgprofMaxSeconds is the upper clamp applied to the seconds query
	// parameter accepted by /debug/fgprof. Larger values are silently lowered
	// to this clamp; smaller values are accepted as-is.
	fgprofMaxSeconds = 60

	// fgprofHandlerTimeout is the hard upper bound on how long a single
	// /debug/fgprof request is allowed to run end-to-end. It is set slightly
	// above fgprofMaxSeconds so that a well-formed clamped profile has time
	// to complete and flush, while a stuck handler is still released.
	fgprofHandlerTimeout = 65 * time.Second
)

// fgprofInProgress acts as a mutual-exclusion flag: at most one fgprof profile
// may run at any given time, mirroring runtime/pprof's profile already in
// progress behaviour. Accessed via sync/atomic so no additional lock is
// required.
var fgprofInProgress int32

// fgprofHandler wraps the vendored fgprof.Handler() with three guardrails
// recommended by the linked finding: (1) clamp the caller-controlled
// seconds parameter to fgprofMaxSeconds, (2) serialize so at most one
// profile runs at a time, and (3) enforce an http.TimeoutHandler deadline on
// the request.
func fgprofHandler() http.Handler {
	inner := fgprof.Handler()

	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serialize: refuse concurrent profiles rather than letting each
		// request spin up its own 99 Hz stop-the-world sampler.
		if !atomic.CompareAndSwapInt32(&fgprofInProgress, 0, 1) {
			http.Error(w, "fgprof: profile already in progress\n", http.StatusTooManyRequests)
			return
		}
		defer atomic.StoreInt32(&fgprofInProgress, 0)

		// Clamp the seconds query parameter in place. We rewrite the
		// request URL rather than invoking fgprof internals because the
		// vendored handler re-parses the query itself. Negative or invalid
		// values are left alone so the upstream handler returns its usual
		// 400 Bad Request.
		if s := r.URL.Query().Get("seconds"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > fgprofMaxSeconds {
				q := r.URL.Query()
				q.Set("seconds", strconv.Itoa(fgprofMaxSeconds))
				r2 := r.Clone(r.Context())
				r2.URL.RawQuery = q.Encode()
				r = r2
			}
		}

		inner.ServeHTTP(w, r)
	})

	// Hard upper bound on request lifetime. fgprof uses time.Sleep internally
	// which does not respect request cancellation, but TimeoutHandler ensures
	// the HTTP response is closed and the server goroutine is not held even
	// if the sampler fails to stop.
	return http.TimeoutHandler(guarded, fgprofHandlerTimeout, "fgprof: handler timeout\n")
}
