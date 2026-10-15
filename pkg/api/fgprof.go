package api

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/felixge/fgprof"
)

// maxFgprofSeconds is the maximum profile duration accepted by the Cortex
// fgprof wrapper. The vendored fgprof handler accepts any positive int for
// the seconds query argument, which lets a caller pin a stop-the-world
// profiler for an effectively unbounded time. We clamp the value to a small
// operator-friendly maximum.
const maxFgprofSeconds = 60

// defaultFgprofSeconds mirrors the default used by the vendored fgprof
// handler when seconds is not provided.
const defaultFgprofSeconds = 30

// fgprofInFlight is a process-wide single-in-flight guard for the fgprof
// endpoint. fgprof.Start spawns a 99Hz goroutine that repeatedly calls
// runtime.GoroutineProfile, which stops the world; allowing concurrent
// profiles multiplies the stop-the-world pause rate across all tenants
// sharing the process.
var fgprofInFlight int32

// FgprofHandler returns the Cortex-owned wrapper around fgprof.Handler used
// at /debug/fgprof. Compared to calling fgprof.Handler directly it:
//
//   - clamps the seconds query parameter to [1, maxFgprofSeconds] so a
//     single request cannot pin the stop-the-world profiler for the life
//     of the process;
//   - rejects a second concurrent profile with 429 Too Many Requests, so
//     multiple callers cannot multiply the stop-the-world pause rate;
//   - rejects the request early when the request context is already
//     cancelled, so trivially-aborted clients do not consume a profile
//     slot.
//
// The response shape of a successful profile is unchanged: the request is
// forwarded to the underlying fgprof handler with a validated seconds value.
func FgprofHandler() http.Handler {
	inner := fgprof.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.Context().Err(); err != nil {
			// Client already gone; do not start a sampler.
			http.Error(w, "request cancelled", 499)
			return
		}

		q := r.URL.Query()
		seconds := defaultFgprofSeconds
		if s := q.Get("seconds"); s != "" {
			parsed, err := strconv.Atoi(s)
			if err != nil || parsed <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "bad seconds: %q: %v\n", s, err)
				return
			}
			seconds = parsed
		}
		if seconds > maxFgprofSeconds {
			seconds = maxFgprofSeconds
		}

		if !atomic.CompareAndSwapInt32(&fgprofInFlight, 0, 1) {
			w.Header().Set("Retry-After", strconv.Itoa(maxFgprofSeconds))
			http.Error(w, "another fgprof profile is already in progress", http.StatusTooManyRequests)
			return
		}
		defer atomic.StoreInt32(&fgprofInFlight, 0)

		// Rewrite the request with the validated/clamped seconds so the
		// underlying fgprof handler cannot observe an unbounded value.
		req := r.Clone(r.Context())
		values := req.URL.Query()
		values.Set("seconds", strconv.Itoa(seconds))
		req.URL.RawQuery = values.Encode()

		inner.ServeHTTP(w, req)
	})
}
