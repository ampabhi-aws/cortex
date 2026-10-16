package limiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimiter_RecheckPeriod(t *testing.T) {
	strategy := &increasingLimitStrategy{}
	limiter := NewRateLimiter(strategy, 10*time.Second)
	now := time.Now()

	// Since the strategy increases the limit and burst value each time
	// the strategy functions are called, we do assert if the recheck
	// period is honored increasing the input time
	assert.Equal(t, float64(1), limiter.Limit(now, "test"))
	assert.Equal(t, 1, limiter.Burst(now, "test"))

	assert.Equal(t, float64(1), limiter.Limit(now.Add(9*time.Second), "test"))
	assert.Equal(t, 1, limiter.Burst(now.Add(9*time.Second), "test"))

	assert.Equal(t, float64(2), limiter.Limit(now.Add(10*time.Second), "test"))
	assert.Equal(t, 2, limiter.Burst(now.Add(10*time.Second), "test"))

	assert.Equal(t, float64(2), limiter.Limit(now.Add(19*time.Second), "test"))
	assert.Equal(t, 2, limiter.Burst(now.Add(19*time.Second), "test"))

	assert.Equal(t, float64(3), limiter.Limit(now.Add(20*time.Second), "test"))
	assert.Equal(t, 3, limiter.Burst(now.Add(20*time.Second), "test"))
}

func TestRateLimiter_AllowN(t *testing.T) {
	strategy := &staticLimitStrategy{tenants: map[string]struct {
		limit float64
		burst int
	}{
		"tenant-1": {limit: 10, burst: 20},
		"tenant-2": {limit: 20, burst: 40},
	}}

	limiter := NewRateLimiter(strategy, 10*time.Second)
	now := time.Now()

	// Tenant #1
	assert.Equal(t, true, limiter.AllowN(now, "tenant-1", 8))
	assert.Equal(t, true, limiter.AllowN(now, "tenant-1", 10))
	assert.Equal(t, false, limiter.AllowN(now, "tenant-1", 3))
	assert.Equal(t, true, limiter.AllowN(now, "tenant-1", 2))

	assert.Equal(t, true, limiter.AllowN(now.Add(time.Second), "tenant-1", 8))
	assert.Equal(t, false, limiter.AllowN(now.Add(time.Second), "tenant-1", 3))
	assert.Equal(t, true, limiter.AllowN(now.Add(time.Second), "tenant-1", 2))

	// Tenant #2
	assert.Equal(t, true, limiter.AllowN(now, "tenant-2", 18))
	assert.Equal(t, true, limiter.AllowN(now, "tenant-2", 20))
	assert.Equal(t, false, limiter.AllowN(now, "tenant-2", 3))
	assert.Equal(t, true, limiter.AllowN(now, "tenant-2", 2))

	assert.Equal(t, true, limiter.AllowN(now.Add(time.Second), "tenant-2", 18))
	assert.Equal(t, false, limiter.AllowN(now.Add(time.Second), "tenant-2", 3))
	assert.Equal(t, true, limiter.AllowN(now.Add(time.Second), "tenant-2", 2))
}

func TestRateLimiter_RemoveTenant(t *testing.T) {
	strategy := &staticLimitStrategy{tenants: map[string]struct {
		limit float64
		burst int
	}{
		"tenant-1": {limit: 10, burst: 20},
	}}

	limiter := NewRateLimiter(strategy, 10*time.Second)
	now := time.Now()

	// Prime a per-tenant entry.
	assert.Equal(t, true, limiter.AllowN(now, "tenant-1", 1))
	limiter.tenantsLock.RLock()
	_, exists := limiter.tenants["tenant-1"]
	limiter.tenantsLock.RUnlock()
	assert.True(t, exists, "entry should be present after use")

	// Remove it; the map entry must be gone.
	limiter.RemoveTenant("tenant-1")
	limiter.tenantsLock.RLock()
	_, exists = limiter.tenants["tenant-1"]
	limiter.tenantsLock.RUnlock()
	assert.False(t, exists, "entry should be removed after RemoveTenant")

	// Removing a non-existent tenant is a safe no-op.
	limiter.RemoveTenant("never-seen")

	// After removal, the limiter can be reused and a fresh entry is
	// created on next use.
	assert.Equal(t, true, limiter.AllowN(now, "tenant-1", 1))
	limiter.tenantsLock.RLock()
	_, exists = limiter.tenants["tenant-1"]
	limiter.tenantsLock.RUnlock()
	assert.True(t, exists, "entry should be re-created after use post-removal")
}

func BenchmarkRateLimiter_CustomMultiTenant(b *testing.B) {
	strategy := &increasingLimitStrategy{}
	limiter := NewRateLimiter(strategy, 10*time.Second)
	now := time.Now()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		limiter.AllowN(now, "test", 1)
	}
}

func BenchmarkRateLimiter_OriginalSingleTenant(b *testing.B) {
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	now := time.Now()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		limiter.AllowN(now, 1)
	}
}

type increasingLimitStrategy struct {
	limit float64
	burst int
}

func (s *increasingLimitStrategy) Limit(tenantID string) float64 {
	s.limit++
	return s.limit
}

func (s *increasingLimitStrategy) Burst(tenantID string) int {
	s.burst++
	return s.burst
}

type staticLimitStrategy struct {
	tenants map[string]struct {
		limit float64
		burst int
	}
}

func (s *staticLimitStrategy) Limit(tenantID string) float64 {
	tenant, ok := s.tenants[tenantID]
	if !ok {
		return 0
	}

	return tenant.limit
}

func (s *staticLimitStrategy) Burst(tenantID string) int {
	tenant, ok := s.tenants[tenantID]
	if !ok {
		return 0
	}

	return tenant.burst
}
