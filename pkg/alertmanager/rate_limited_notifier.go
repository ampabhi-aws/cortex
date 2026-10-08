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

func newRateLimitedNotifier(upstream notify.Notifier, limits rateLimits, recheckInterval time.Duration, counter prometheus.Counter) *rateLimitedNotifier {
	return newRateLimitedNotifierWithLimiter(upstream, limits, rate.NewLimiter(limits.RateLimit(), limits.Burst()), recheckInterval, counter)
}

// newRateLimitedNotifierWithLimiter wraps upstream with a rate-limited notifier
// that uses the supplied, caller-owned *rate.Limiter. Callers can share a
// single limiter across multiple notifier instances (for example, every
// webhook_configs[] entry of a tenant) so the enforced rate matches the
// documented per-user semantics instead of being multiplied by the number of
// integration instances. The limiter is also persistent across ApplyConfig
// reloads when the caller keeps it alive, which prevents config churn from
// resetting the token bucket.
func newRateLimitedNotifierWithLimiter(upstream notify.Notifier, limits rateLimits, limiter *rate.Limiter, recheckInterval time.Duration, counter prometheus.Counter) *rateLimitedNotifier {
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
