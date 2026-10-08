package cortexpb

import (
	"errors"
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

func TestPreallocWriteRequest_Unmarshal_MaxTimeseriesCap(t *testing.T) {
	// Save and restore the global cap so the test is hermetic.
	original := maxTimeseriesPerRequest
	t.Cleanup(func() { maxTimeseriesPerRequest = original })

	// Build a WriteRequest wire payload with N empty timeseries elements.
	// Each element is encoded as tag 1 / wiretype 2 (0x0a) and a 0-byte length (0x00).
	build := func(n int) []byte {
		buf := make([]byte, 0, 2*n)
		for i := 0; i < n; i++ {
			buf = append(buf, 0x0a, 0x00)
		}
		return buf
	}

	t.Run("request at the cap is accepted", func(t *testing.T) {
		maxTimeseriesPerRequest = 10
		var req PreallocWriteRequest
		require.NoError(t, req.Unmarshal(build(10)))
		assert.Len(t, req.Timeseries, 10)
		ReuseSlice(req.Timeseries)
	})

	t.Run("request above the cap is rejected and does not leak elements", func(t *testing.T) {
		maxTimeseriesPerRequest = 10
		var req PreallocWriteRequest
		err := req.Unmarshal(build(11))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTooManyTimeseries), "expected ErrTooManyTimeseries, got %v", err)
		assert.Nil(t, req.Timeseries)
		assert.Nil(t, req.Metadata)
	})

	t.Run("cap of 0 disables the check", func(t *testing.T) {
		maxTimeseriesPerRequest = 0
		var req PreallocWriteRequest
		require.NoError(t, req.Unmarshal(build(1000)))
		assert.Len(t, req.Timeseries, 1000)
		ReuseSlice(req.Timeseries)
	})
}
