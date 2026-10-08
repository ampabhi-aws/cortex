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

func TestPreallocTimeseriesUnmarshal_EmptyEntrySkipsPool(t *testing.T) {
	// A zero-length wire entry must NOT eagerly allocate ~936 bytes of
	// label/sample/exemplar backing arrays via the pool. This guards against
	// the remote-write allocation-amplification bomb (CWE-770).
	var p PreallocTimeseries
	require.NoError(t, p.Unmarshal(nil))
	require.NotNil(t, p.TimeSeries)
	assert.Equal(t, 0, cap(p.TimeSeries.Labels))
	assert.Equal(t, 0, cap(p.TimeSeries.Samples))
	assert.Equal(t, 0, cap(p.TimeSeries.Exemplars))
}

func TestPreallocWriteRequestUnmarshal_RejectsPreCheck(t *testing.T) {
	orig := maxTimeseriesPerRequest
	t.Cleanup(func() { maxTimeseriesPerRequest = orig })
	maxTimeseriesPerRequest = 10

	// Each repeated entry costs at least 2 bytes on the wire, so a body of
	// 2*(max+1)+1 bytes could encode more than max entries and must be
	// rejected before any parsing happens.
	body := make([]byte, 2*(maxTimeseriesPerRequest+1)+1)
	var p PreallocWriteRequest
	err := p.Unmarshal(body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many series")
}

func TestPreallocWriteRequestUnmarshal_DisabledByZero(t *testing.T) {
	orig := maxTimeseriesPerRequest
	t.Cleanup(func() { maxTimeseriesPerRequest = orig })
	maxTimeseriesPerRequest = 0

	// Even a large body with many empty entries is accepted when the limit
	// is disabled (operator opt-out).
	n := 1000
	body := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		body = append(body, 0x0a, 0x00)
	}
	var p PreallocWriteRequest
	require.NoError(t, p.Unmarshal(body))
	assert.Len(t, p.Timeseries, n)
	ReuseSlice(p.Timeseries)
}
