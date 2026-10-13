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

// newRateLimitedNotifier wraps upstream in a rate-limited notifier.
//
// If limiter is non-nil, the provided *rate.Limiter is reused (and shared) by
// the returned notifier. This is used by the Alertmanager to keep a single
// token bucket per (tenant, integration-name) across all integration
// *instances* in a tenant's config, and to preserve the bucket state across
// ApplyConfig calls (a tenant must not be able to refill its burst allowance
// by re-uploading a trivially-modified config).
//
// If limiter is nil, a fresh *rate.Limiter is created from the current
// limits.
func newRateLimitedNotifier(upstream notify.Notifier, limits rateLimits, recheckInterval time.Duration, counter prometheus.Counter, limiter ...*rate.Limiter) *rateLimitedNotifier {
	var l *rate.Limiter
	if len(limiter) > 0 && limiter[0] != nil {
		l = limiter[0]
	} else {
		l = rate.NewLimiter(limits.RateLimit(), limits.Burst())
	}
	return &rateLimitedNotifier{
		upstream:        upstream,
		counter:         counter,
		limits:          limits,
		limiter:         l,
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
