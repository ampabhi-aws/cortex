// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/felixge/fgprof"
)

// Limits enforced on the /debug/fgprof endpoint. The vendored fgprof handler
// accepts an unbounded "seconds" query parameter and starts a new 99 Hz
// runtime.GoroutineProfile sampler per request with no package-level profile
// lock. On a service like Cortex, which routinely runs many goroutines, this
// is a cheap-to-trigger, potentially expensive, stop-the-world CPU
// exhaustion primitive. We cap both the per-request duration and the number
// of concurrent profiles so that an operator who exposes the admin surface
// cannot be trivially stalled.
const (
	// fgprofMaxSeconds is the hard upper bound on the "seconds" query argument.
	fgprofMaxSeconds = 120

	// fgprofMaxConcurrent bounds the number of simultaneous fgprof profiles.
	// Each profile runs an independent 99 Hz runtime.GoroutineProfile loop,
	// so unbounded concurrency multiplies the stop-the-world cost linearly.
	fgprofMaxConcurrent = 2
)

// fgprofHandler returns an http.Handler that wraps fgprof.Handler() with
// defense-in-depth limits: a hard upper bound on the "seconds" query
// parameter and a global concurrency limit. This matches Cortex's deployment
// model, where the admin surface is expected to be gated by an external
// reverse proxy, but prevents a trivial self-DoS when it is not.
func fgprofHandler() http.Handler {
	var inFlight int64
	inner := fgprof.Handler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate "seconds" before admitting the request so that a caller
		// cannot pin a sampling slot with a very long profile.
		if s := r.URL.Query().Get("seconds"); s != "" {
			seconds, err := strconv.Atoi(s)
			if err != nil || seconds <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "bad seconds: %q\n", s)
				return
			}
			if seconds > fgprofMaxSeconds {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "seconds must be <= %d\n", fgprofMaxSeconds)
				return
			}
		}

		// Bound in-flight profiles. runtime.GoroutineProfile is stop-the-world
		// and scales with the number of goroutines; without this guard, N
		// concurrent requests produce N independent 99 Hz STW loops.
		if n := atomic.AddInt64(&inFlight, 1); n > fgprofMaxConcurrent {
			atomic.AddInt64(&inFlight, -1)
			w.Header().Set("Retry-After", "30")
			http.Error(w, "too many concurrent fgprof requests", http.StatusTooManyRequests)
			return
		}
		defer atomic.AddInt64(&inFlight, -1)

		inner.ServeHTTP(w, r)
	})
}
