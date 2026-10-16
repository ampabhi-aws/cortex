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

// TestPreallocTimeseriesUnmarshalRejectsEmpty verifies that an empty encoded
// TimeSeries entry on the wire is rejected rather than pulling a fresh pooled
// (~930 byte) *TimeSeries. See CWE-770: without this guard a highly compressible
// remote_write body of repeated 0x0A 0x00 pairs can allocate tens of GB of heap
// inside the push-path unmarshal and OOM-kill the distributor before any
// per-request or per-tenant limit runs.
func TestPreallocTimeseriesUnmarshalRejectsEmpty(t *testing.T) {
	p := &PreallocTimeseries{}
	err := p.Unmarshal(nil)
	require.Error(t, err)

	err = p.Unmarshal([]byte{})
	require.Error(t, err)
}

// TestPreallocWriteRequestRejectsEmptyTimeseries exercises the full generated
// WriteRequest.Unmarshal path: a buffer consisting of the 2-byte sequence
// `0x0A 0x00` (field 1, wire type 2, length 0) is the minimal exploit payload
// (see finding 01a142c027057bedb83d91c6f1568cec); it must be rejected and must
// not cause an allocation per element.
func TestPreallocWriteRequestRejectsEmptyTimeseries(t *testing.T) {
	req := &PreallocWriteRequest{}
	err := req.Unmarshal([]byte{0x0A, 0x00})
	require.Error(t, err)
}
