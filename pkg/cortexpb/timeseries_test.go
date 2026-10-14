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

// TestPreallocTimeseries_UnmarshalEmptyEntryIsNotPooled verifies that an empty
// TimeSeries entry does not pull a fat pre-allocated *TimeSeries from the
// pool. This defends against a DoS vector where millions of 2-byte empty
// entries in a single WriteRequest would otherwise retain ~930 bytes of
// heap each inside PreallocWriteRequest.Unmarshal.
func TestPreallocTimeseries_UnmarshalEmptyEntryIsNotPooled(t *testing.T) {
	var p PreallocTimeseries
	require.NoError(t, p.Unmarshal(nil))
	require.NotNil(t, p.TimeSeries)
	assert.Equal(t, 0, cap(p.TimeSeries.Labels), "empty entry must not get a pre-allocated Labels slice")
	assert.Equal(t, 0, cap(p.TimeSeries.Samples), "empty entry must not get a pre-allocated Samples slice")
	assert.Equal(t, 0, cap(p.TimeSeries.Exemplars), "empty entry must not get a pre-allocated Exemplars slice")
}

// TestPreallocTimeseries_UnmarshalPopulatedEntryUsesPool verifies that
// legitimate entries with labels or samples still go through the pre-allocated
// pool, preserving decode performance for real traffic.
func TestPreallocTimeseries_UnmarshalPopulatedEntryUsesPool(t *testing.T) {
	// Drain the pool so New() runs deterministically.
	for i := 0; i < 32; i++ {
		_ = timeSeriesPool.Get()
	}
	src := &TimeSeries{
		Labels:  []LabelAdapter{{Name: "__name__", Value: "up"}},
		Samples: []Sample{{Value: 1, TimestampMs: 2}},
	}
	buf, err := src.Marshal()
	require.NoError(t, err)

	var p PreallocTimeseries
	require.NoError(t, p.Unmarshal(buf))
	require.NotNil(t, p.TimeSeries)
	assert.Equal(t, src.Labels, p.TimeSeries.Labels)
	assert.Equal(t, src.Samples, p.TimeSeries.Samples)
	assert.GreaterOrEqual(t, cap(p.TimeSeries.Labels), 1)
}

func Test_timeseriesEntryIsEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"nil", nil, true},
		{"empty slice", []byte{}, true},
		{"field 1 labels present (len 0 inner)", []byte{0x0a, 0x00}, false},
		{"field 2 samples present", []byte{0x12, 0x00}, false},
		{"field 3 exemplars present", []byte{0x1a, 0x00}, false},
		// field 100, wire type 0 (varint). tag = (100<<3)|0 = 800 = 0x320.
		// Varint-encoded: low 7 bits 0x20 (|0x80 continuation) then 0x06.
		{"unknown varint field only", []byte{0xa0, 0x06, 0x00}, true},
		{"truncated varint", []byte{0x80}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, timeseriesEntryIsEmpty(tc.in))
		})
	}
}
