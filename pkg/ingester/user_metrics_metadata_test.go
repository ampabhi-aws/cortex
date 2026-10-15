package ingester

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// TestUserMetricsMetadata_DiscardedMetadataLabelOrder guards against the
// previous bug where the (reason, user) label order expected by
// validation.DiscardedMetadata was swapped at the two ingester call sites.
// A regression would land the tenant ID in the "reason" label (unbounded
// cardinality) and the reason constant in the "user" label, which
// defeats the per-tenant metric cleanup in DeletePerUserValidationMetrics.
func TestUserMetricsMetadata_DiscardedMetadataLabelOrder(t *testing.T) {
	const userID = "tenant-A"

	// Reset DiscardedMetadata to isolate assertions from any other test
	// that may have incremented it.
	validation.DiscardedMetadata.Reset()
	t.Cleanup(func() { validation.DiscardedMetadata.Reset() })

	// A ring with a single healthy ingester and one zone.
	ring := &ringCountMock{}
	ring.On("HealthyInstancesCount").Return(1)
	ring.On("ZonesCount").Return(1)

	limits, err := validation.NewOverrides(validation.Limits{
		MaxLocalMetricsWithMetadataPerUser: 1,
		MaxLocalMetadataPerMetric:          1,
	}, nil)
	require.NoError(t, err)

	limiter := NewLimiter(limits, ring, util.ShardingStrategyDefault, false, 1, false)
	metrics := newIngesterMetrics(prometheus.NewPedanticRegistry(), false, false, func() *InstanceLimits { return nil }, nil, nil)
	mm := newMetadataMap(limiter, metrics, userID)

	// First metadata for metric "m1" is accepted.
	require.NoError(t, mm.add("m1", &cortexpb.MetricMetadata{MetricFamilyName: "m1", Help: "h0"}))

	// A second distinct metadata entry for "m1" trips the per-metric
	// metadata limit (MaxLocalMetadataPerMetric=1).
	require.Error(t, mm.add("m1", &cortexpb.MetricMetadata{MetricFamilyName: "m1", Help: "h1"}))

	// Adding metadata for a new metric name trips the per-user
	// metrics-with-metadata limit (MaxLocalMetricsWithMetadataPerUser=1).
	require.Error(t, mm.add("m2", &cortexpb.MetricMetadata{MetricFamilyName: "m2", Help: "h0"}))

	// The emitted series must carry reason in the "reason" label and
	// the tenant ID in the "user" label; the opposite order would mean
	// the tenant ID is written to "reason" (the bug).
	assert.Equal(t, 1.0, testutil.ToFloat64(validation.DiscardedMetadata.WithLabelValues(perMetricMetadataLimit, userID)),
		"expected one increment at reason=%q, user=%q", perMetricMetadataLimit, userID)
	assert.Equal(t, 1.0, testutil.ToFloat64(validation.DiscardedMetadata.WithLabelValues(perUserMetadataLimit, userID)),
		"expected one increment at reason=%q, user=%q", perUserMetadataLimit, userID)

	// And nothing must have landed under the swapped order (tenant ID
	// used as reason).
	assert.Equal(t, 0.0, testutil.ToFloat64(validation.DiscardedMetadata.WithLabelValues(userID, perMetricMetadataLimit)),
		"tenant ID must not appear in the reason label")
	assert.Equal(t, 0.0, testutil.ToFloat64(validation.DiscardedMetadata.WithLabelValues(userID, perUserMetadataLimit)),
		"tenant ID must not appear in the reason label")
}
