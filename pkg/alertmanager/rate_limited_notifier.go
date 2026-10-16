package alertmanager

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/atomic"
	"golang.org/x/time/rate"
)

type rateLimits interface {
	RateLimit() rate.Limit
	Burst() int
}

type rateLimitedNotifier struct {
	upstream notify.Notifier
	counter  prometheus.Counter

	limiter *rate.Limiter
	limits  rateLimits

	recheckInterval time.Duration
	recheckAt       atomic.Int64 // unix nanoseconds timestamp
}

// newRateLimitedNotifier builds a rateLimitedNotifier that shares the given
// *rate.Limiter across every notifier instance built with it. The limiter is
// typically owned by the Alertmanager instance (keyed by integration name)
// so that a tenant cannot multiply its per-tenant/per-integration-name
// notification quota by adding more *_configs entries to its own configuration.
// If limiter is nil, a dedicated limiter is created from `limits` for backward
// compatibility with callers that do not own a shared limiter (e.g. tests).
func newRateLimitedNotifier(upstream notify.Notifier, limits rateLimits, recheckInterval time.Duration, counter prometheus.Counter, limiter *rate.Limiter) *rateLimitedNotifier {
	if limiter == nil {
		limiter = rate.NewLimiter(limits.RateLimit(), limits.Burst())
	}
	return &rateLimitedNotifier{
		upstream:        upstream,
		counter:         counter,
		limits:          limits,
		limiter:         limiter,
		recheckInterval: recheckInterval,
	}
}

var errRateLimited = errors.New("failed to notify due to rate limits")

func (r *rateLimitedNotifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {
	now := time.Now()
	if now.UnixNano() >= r.recheckAt.Load() {
		if limit := r.limits.RateLimit(); r.limiter.Limit() != limit {
			r.limiter.SetLimitAt(now, limit)
		}

		if burst := r.limits.Burst(); r.limiter.Burst() != burst {
			r.limiter.SetBurstAt(now, burst)
		}

		r.recheckAt.Store(now.UnixNano() + r.recheckInterval.Nanoseconds())
	}

	// This counts as single notification, no matter how many alerts there are in it.
	if !r.limiter.AllowN(now, 1) {
		r.counter.Inc()
		// Don't retry this notification later.
		return false, errRateLimited
	}

	return r.upstream.Notify(ctx, alerts...)
}
