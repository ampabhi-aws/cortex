package alertmanager

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimitedNotifier(t *testing.T) {
	mock := &mockNotifier{}
	counter := prometheus.NewCounter(prometheus.CounterOpts{})

	// Initial limits.
	limiter := &limiter{limit: 5, burst: 5}
	rateLimitedNotifier := newRateLimitedNotifier(mock, limiter, 10*time.Second, counter)

	runNotifications(t, rateLimitedNotifier, counter, 10, 5, 5, 5)

	// Disable limits.
	limiter.limit = rate.Inf
	limiter.burst = 0

	runNotifications(t, rateLimitedNotifier, counter, 10, 10, 0, 5)

	limiter.limit = 5
	limiter.burst = 5

	// We don't get any successful notifications until some time passes.
	runNotifications(t, rateLimitedNotifier, counter, 10, 0, 10, 15)

	time.Sleep(1 * time.Second) // Wait to refill rate-limiter's "bucket".
	runNotifications(t, rateLimitedNotifier, counter, 10, 5, 5, 20)
}

func runNotifications(t *testing.T, rateLimitedNotifier *rateLimitedNotifier, counter prometheus.Counter, count, expectedSuccess, expectedRateLimited, expectedCounter int) {
	rateLimitedNotifier.recheckAt.Store(0) // Force recheck of limits.

	success := 0
	rateLimited := 0

	for i := 0; i < count; i++ {
		retry, err := rateLimitedNotifier.Notify(context.Background(), &types.Alert{})

		if err == nil {
			success++
		} else if err == errRateLimited {
			rateLimited++
			assert.False(t, retry)
		} else {
			assert.NotNil(t, err)
		}
	}

	assert.Equal(t, expectedSuccess, success)
	assert.Equal(t, expectedRateLimited, rateLimited)
	assert.Equal(t, expectedCounter, int(testutil.ToFloat64(counter)))
}

// TestRateLimitedNotifier_SharedLimiter verifies that when multiple
// rateLimitedNotifier instances share a single *rate.Limiter (as happens when a
// tenant declares K integration entries pointing at the same integration), the
// aggregate rate across all K notifiers equals the configured per-tenant limit
// — not K times the configured limit.
func TestRateLimitedNotifier_SharedLimiter(t *testing.T) {
	const k = 10
	counter := prometheus.NewCounter(prometheus.CounterOpts{})
	lim := &limiter{limit: 1, burst: 1}
	shared := rate.NewLimiter(lim.RateLimit(), lim.Burst())

	notifiers := make([]*rateLimitedNotifier, 0, k)
	for i := 0; i < k; i++ {
		notifiers = append(notifiers, newRateLimitedNotifierWithLimiter(&mockNotifier{}, lim, shared, 10*time.Second, counter))
	}

	// Fire one notification per notifier. Only ONE must succeed in total,
	// matching the aggregate 1/sec per-tenant limit, even though there are k notifiers.
	success := 0
	rateLimited := 0
	for _, n := range notifiers {
		n.recheckAt.Store(0)
		_, err := n.Notify(context.Background(), &types.Alert{})
		switch err {
		case nil:
			success++
		case errRateLimited:
			rateLimited++
		default:
			t.Fatalf("unexpected err: %v", err)
		}
	}
	assert.Equal(t, 1, success, "K notifiers sharing a 1-token bucket must deliver exactly one notification per second in total")
	assert.Equal(t, k-1, rateLimited)
}

// TestRateLimitedNotifier_ChargesPerAlert verifies that one notification
// carrying a large alert batch is charged proportionally and cannot bypass the
// configured rate budget.
func TestRateLimitedNotifier_ChargesPerAlert(t *testing.T) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{})
	lim := &limiter{limit: 10, burst: 10}
	n := newRateLimitedNotifier(&mockNotifier{}, lim, 10*time.Second, counter)

	n.recheckAt.Store(0)
	alerts := make([]*types.Alert, 5)
	for i := range alerts {
		alerts[i] = &types.Alert{}
	}
	// One notification carrying 5 alerts should consume 5 tokens.
	_, err := n.Notify(context.Background(), alerts...)
	assert.NoError(t, err)

	// Another batch of 6 would exceed the remaining 5 tokens.
	alerts = append(alerts, &types.Alert{})
	_, err = n.Notify(context.Background(), alerts...)
	assert.Equal(t, errRateLimited, err)
}

type mockNotifier struct{}

func (m *mockNotifier) Notify(ctx context.Context, alert ...*types.Alert) (bool, error) {
	return false, nil
}

type limiter struct {
	limit rate.Limit
	burst int
}

func (l *limiter) RateLimit() rate.Limit {
	return l.limit
}

func (l *limiter) Burst() int {
	return l.burst
}
