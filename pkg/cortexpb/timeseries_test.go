package cortexpb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelAdapter_Marshal(t *testing.T) {
	tests := []struct {
		bs *LabelAdapter
	}{
		{&LabelAdapter{Name: "foo", Value: "bar"}},
		{&LabelAdapter{Name: "very long label name", Value: "very long label value"}},
		{&LabelAdapter{Name: "", Value: "foo"}},
		{&LabelAdapter{}},
	}
	for _, tt := range tests {
		t.Run(tt.bs.Name, func(t *testing.T) {
			bytes, err := tt.bs.Marshal()
			require.NoError(t, err)
			lbs := &LabelAdapter{}
			require.NoError(t, lbs.Unmarshal(bytes))
			require.EqualValues(t, tt.bs, lbs)
		})
	}
}

func TestPreallocTimeseriesSliceFromPool(t *testing.T) {
	t.Run("new instance is provided when not available to reuse", func(t *testing.T) {
		first := PreallocTimeseriesSliceFromPool()
		second := PreallocTimeseriesSliceFromPool()

		assert.NotSame(t, first, second)
	})

	t.Run("instance is cleaned before reusing", func(t *testing.T) {
		slice := PreallocTimeseriesSliceFromPool()
		slice = append(slice, PreallocTimeseries{TimeSeries: &TimeSeries{}})
		ReuseSlice(slice)

		reused := PreallocTimeseriesSliceFromPool()
		assert.Len(t, reused, 0)
	})
}

func TestTimeseriesFromPool(t *testing.T) {
	t.Run("new instance is provided when not available to reuse", func(t *testing.T) {
		first := TimeseriesFromPool()
		second := TimeseriesFromPool()

		assert.NotSame(t, first, second)
	})

	t.Run("instance is cleaned before reusing", func(t *testing.T) {
		ts := TimeseriesFromPool()
		ts.Labels = []LabelAdapter{{Name: "foo", Value: "bar"}}
		ts.Samples = []Sample{{Value: 1, TimestampMs: 2}}
		ReuseTimeseries(ts)

		reused := TimeseriesFromPool()
		assert.Len(t, reused.Labels, 0)
		assert.Len(t, reused.Samples, 0)
	})
}

func TestPreallocWriteRequest_Unmarshal_EnforcesSeriesCap(t *testing.T) {
	// Build a WriteRequest wire payload of N empty TimeSeries entries
	// (field 1, wire type 2, length 0 == bytes {0x0a, 0x00}).
	const n = 50
	payload := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		payload = append(payload, 0x0a, 0x00)
	}

	t.Run("accepts request below cap", func(t *testing.T) {
		prev := maxSeriesPerWriteRequest
		t.Cleanup(func() { SetMaxSeriesPerWriteRequest(prev) })
		SetMaxSeriesPerWriteRequest(n + 1)

		var req PreallocWriteRequest
		require.NoError(t, req.Unmarshal(payload))
		assert.Len(t, req.Timeseries, n)
		ReuseSlice(req.Timeseries)
	})

	t.Run("rejects request above cap", func(t *testing.T) {
		prev := maxSeriesPerWriteRequest
		t.Cleanup(func() { SetMaxSeriesPerWriteRequest(prev) })
		SetMaxSeriesPerWriteRequest(n - 1)

		var req PreallocWriteRequest
		err := req.Unmarshal(payload)
		require.ErrorIs(t, err, ErrTooManySeriesPerRequest)
		assert.Nil(t, req.Timeseries)
	})

	t.Run("cap of zero disables the check", func(t *testing.T) {
		prev := maxSeriesPerWriteRequest
		t.Cleanup(func() { SetMaxSeriesPerWriteRequest(prev) })
		SetMaxSeriesPerWriteRequest(0)

		var req PreallocWriteRequest
		require.NoError(t, req.Unmarshal(payload))
		assert.Len(t, req.Timeseries, n)
		ReuseSlice(req.Timeseries)
	})
}

func TestPreallocTimeseries_Unmarshal_SkipsPoolForTinyPayloads(t *testing.T) {
	// Drain the pool so a subsequent Get would re-run New(), making an
	// over-allocation observable via the returned slice capacity.
	for i := 0; i < 32; i++ {
		_ = TimeseriesFromPool()
	}

	var p PreallocTimeseries
	require.NoError(t, p.Unmarshal(nil))
	require.NotNil(t, p.TimeSeries)
	// A lazily-grown TimeSeries starts with nil (0-capacity) slices rather
	// than the pool's preallocated 20/10/1 capacities.
	assert.Equal(t, 0, cap(p.Labels), "tiny payload must not pay for 20-cap Labels backing array")
	assert.Equal(t, 0, cap(p.Samples), "tiny payload must not pay for 10-cap Samples backing array")
	assert.Equal(t, 0, cap(p.Exemplars), "tiny payload must not pay for 1-cap Exemplars backing array")
}
