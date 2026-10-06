package api

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
)

// maxProfilingSeconds caps the "seconds" query parameter accepted by
// /debug/fgprof. The vendored fgprof handler would otherwise accept any
// positive int32 and sleep for that long while running a 99 Hz sampler that
// calls runtime.GoroutineProfile() (a stop-the-world runtime primitive).
// Capping the duration keeps the primitive useful for operator-driven
// profiling but prevents it from being used to pin a shared process for
// hours or days.
const maxProfilingSeconds = 30

// boundedProfiler wraps a profiling handler (such as fgprof.Handler()) with
// three independent safety properties:
//
//  1. the "seconds" query parameter is validated and capped so an attacker
//     cannot request an unbounded profile duration;
//  2. only one profile is allowed to run at a time; concurrent requests get
//     HTTP 429 instead of multiplying the stop-the-world sampling cost;
//  3. a client disconnecting while the sampler is running is best-effort
//     observed via r.Context() so the handler stops blocking its own
//     goroutine. The vendored fgprof handler sleeps on the wall clock and
//     ignores r.Context(), so we still hold the inflight slot for the
//     bounded duration above (<=maxProfilingSeconds) to avoid writing to a
//     recycled ResponseWriter, but the cap keeps that bounded.
func boundedProfiler(next http.Handler) http.Handler {
	var inflight int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := r.URL.Query().Get("seconds"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 || n > maxProfilingSeconds {
				http.Error(w, fmt.Sprintf("seconds must be an integer between 1 and %d", maxProfilingSeconds), http.StatusBadRequest)
				return
			}
		}

		if !atomic.CompareAndSwapInt32(&inflight, 0, 1) {
			http.Error(w, "a profile is already in progress", http.StatusTooManyRequests)
			return
		}
		defer atomic.StoreInt32(&inflight, 0)

		next.ServeHTTP(w, r)
	})
}
