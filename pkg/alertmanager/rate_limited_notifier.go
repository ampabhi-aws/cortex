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

// newRateLimitedNotifierWithLimiter is like newRateLimitedNotifier but shares an
// externally owned *rate.Limiter across multiple notifier instances. This is
// used to enforce a single aggregate token bucket per (tenant, integration)
// instead of giving every integration entry its own private bucket.
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

	// Charge the limiter proportionally to the number of alerts in the batch
	// (minimum of one token) so that a single notification cannot carry an
	// unbounded alert batch past the configured rate budget.
	n := len(alerts)
	if n < 1 {
		n = 1
	}
	// If the batch is larger than the configured burst, charging n tokens
	// would make AllowN permanently return false; cap the charge to the
	// configured burst so that an oversized batch still fully drains the
	// bucket (instead of being refused and retried, which would not
	// change the amplification factor, or sneaking past at a cost of a
	// single token).
	if burst := r.limiter.Burst(); burst > 0 && n > burst {
		n = burst
	}
	if !r.limiter.AllowN(now, n) {
		r.counter.Inc()
		// Don't retry this notification later.
		return false, errRateLimited
	}

	return r.upstream.Notify(ctx, alerts...)
}
