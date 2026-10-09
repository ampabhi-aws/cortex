package cortexpb

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"unsafe"

	"github.com/prometheus/prometheus/model/labels"
)

// minPreallocatedTimeseriesSize is the minimum size (in bytes) of a serialized
// TimeSeries sub-message below which it is cheaper to allocate a zero-value
// *TimeSeries (lazily grown by the generated Unmarshal code) than to take a
// pre-sized object from timeSeriesPool. Taking a pooled object eagerly
// allocates Labels/Samples/Exemplars backing arrays sized for a typical
// series (~928B on amd64), so for tiny/empty series the pool costs orders of
// magnitude more memory than the actual decoded payload.
const minPreallocatedTimeseriesSize = 64

// ErrTooManySeriesPerRequest is returned by PreallocWriteRequest.Unmarshal when
// the decoded WriteRequest contains more TimeSeries than the configured
// per-request limit (-distributor.max-series-per-write-request).
var ErrTooManySeriesPerRequest = errors.New("too many timeseries in write request")

var (
	expectedTimeseries         = 100
	expectedLabels             = 20
	expectedSamplesPerSeries   = 10
	expectedExemplarsPerSeries = 1

	// maxSeriesPerWriteRequest caps the number of TimeSeries that may appear in
	// a single decoded WriteRequest. It defends against a decode-time memory
	// amplification attack where a small snappy-compressed body expands into
	// millions of empty TimeSeries entries, each of which eagerly allocates
	// ~928B via the timeSeriesPool. 0 disables the limit (unlimited, legacy
	// behaviour).
	maxSeriesPerWriteRequest = 100000

	/*
		We cannot pool these as pointer-to-slice because the place we use them is in WriteRequest which is generated from Protobuf
		and we don't have an option to make it a pointer. There is overhead here 24 bytes of garbage every time a PreallocTimeseries
		is re-used. But since the slices are far far larger, we come out ahead.
	*/
	slicePool = sync.Pool{
		New: func() interface{} {
			return make([]PreallocTimeseries, 0, expectedTimeseries)
		},
	}

	timeSeriesPool = sync.Pool{
		New: func() interface{} {
			return &TimeSeries{
				Labels:    make([]LabelAdapter, 0, expectedLabels),
				Samples:   make([]Sample, 0, expectedSamplesPerSeries),
				Exemplars: make([]Exemplar, 0, expectedExemplarsPerSeries),
			}
		},
	}
)

// PreallocConfig configures how structures will be preallocated to optimise
// proto unmarshalling.
type PreallocConfig struct{}

// RegisterFlags registers configuration settings.
func (PreallocConfig) RegisterFlags(f *flag.FlagSet) {
	f.IntVar(&expectedTimeseries, "ingester-client.expected-timeseries", expectedTimeseries, "Expected number of timeseries per request, used for preallocations.")
	f.IntVar(&expectedLabels, "ingester-client.expected-labels", expectedLabels, "Expected number of labels per timeseries, used for preallocations.")
	f.IntVar(&expectedSamplesPerSeries, "ingester-client.expected-samples-per-series", expectedSamplesPerSeries, "Expected number of samples per timeseries, used for preallocations.")
	f.IntVar(&maxSeriesPerWriteRequest, "distributor.max-series-per-write-request", maxSeriesPerWriteRequest, "Maximum number of timeseries accepted in a single remote-write request. The request is rejected during decoding if it contains more series than this limit. 0 to disable (not recommended; a single request can OOM the process).")
}

// SetMaxSeriesPerWriteRequest overrides the per-request series limit at runtime.
// Primarily intended for tests.
func SetMaxSeriesPerWriteRequest(n int) {
	maxSeriesPerWriteRequest = n
}

// PreallocWriteRequest is a WriteRequest which preallocs slices on Unmarshal.
type PreallocWriteRequest struct {
	WriteRequest
}

// Unmarshal implements proto.Message.
func (p *PreallocWriteRequest) Unmarshal(dAtA []byte) error {
	p.Timeseries = PreallocTimeseriesSliceFromPool()
	if err := p.WriteRequest.Unmarshal(dAtA); err != nil {
		return err
	}
	// Reject requests whose decoded object graph exceeds the configured
	// per-request series cap. This bounds the heap paid by a single request
	// (each pooled *TimeSeries eagerly allocates ~928B of backing arrays).
	if maxSeriesPerWriteRequest > 0 && len(p.Timeseries) > maxSeriesPerWriteRequest {
		ReuseSlice(p.Timeseries)
		p.Timeseries = nil
		return ErrTooManySeriesPerRequest
	}
	return nil
}

// PreallocTimeseries is a TimeSeries which preallocs slices on Unmarshal.
type PreallocTimeseries struct {
	*TimeSeries
}

// Unmarshal implements proto.Message.
func (p *PreallocTimeseries) Unmarshal(dAtA []byte) error {
	// Only pay the pooled preallocation cost (Labels cap 20, Samples cap 10,
	// Exemplars cap 1 -- ~928B on amd64) for series whose encoded form is
	// large enough to plausibly use it. Tiny or empty sub-messages (e.g. the
	// 2-byte `0x0a 0x00` memory-bomb payload) get a bare *TimeSeries whose
	// slices grow lazily inside the generated Unmarshal.
	if len(dAtA) < minPreallocatedTimeseriesSize {
		p.TimeSeries = &TimeSeries{}
	} else {
		p.TimeSeries = TimeseriesFromPool()
	}
	return p.TimeSeries.Unmarshal(dAtA)
}

// LabelAdapter is a labels.Label that can be marshalled to/from protos.
type LabelAdapter labels.Label

// Marshal implements proto.Marshaller.
func (bs *LabelAdapter) Marshal() ([]byte, error) {
	size := bs.Size()
	buf := make([]byte, size)
	n, err := bs.MarshalToSizedBuffer(buf[:size])
	if err != nil {
		return nil, err
	}
	return buf[:n], err
}

func (bs *LabelAdapter) MarshalTo(dAtA []byte) (int, error) {
	size := bs.Size()
	return bs.MarshalToSizedBuffer(dAtA[:size])
}

// MarshalTo implements proto.Marshaller.
func (bs *LabelAdapter) MarshalToSizedBuffer(buf []byte) (n int, err error) {
	ls := (*labels.Label)(bs)
	i := len(buf)
	if len(ls.Value) > 0 {
		i -= len(ls.Value)
		copy(buf[i:], ls.Value)
		i = encodeVarintCortex(buf, i, uint64(len(ls.Value)))
		i--
		buf[i] = 0x12
	}
	if len(ls.Name) > 0 {
		i -= len(ls.Name)
		copy(buf[i:], ls.Name)
		i = encodeVarintCortex(buf, i, uint64(len(ls.Name)))
		i--
		buf[i] = 0xa
	}
	return len(buf) - i, nil
}

// Unmarshal a LabelAdapter, implements proto.Unmarshaller.
// NB this is a copy of the autogenerated code to unmarshal a LabelPair,
// with the byte copying replaced with a yoloString.
func (bs *LabelAdapter) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCortex
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LabelPair: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LabelPair: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCortex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthCortex
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthCortex
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			bs.Name = yoloString(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCortex
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthCortex
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthCortex
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			bs.Value = yoloString(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCortex(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCortex
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthCortex
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func yoloString(buf []byte) string {
	return *((*string)(unsafe.Pointer(&buf)))
}

// Size implements proto.Sizer.
func (bs *LabelAdapter) Size() (n int) {
	ls := (*labels.Label)(bs)
	if bs == nil {
		return 0
	}
	var l int
	_ = l
	l = len(ls.Name)
	if l > 0 {
		n += 1 + l + sovCortex(uint64(l))
	}
	l = len(ls.Value)
	if l > 0 {
		n += 1 + l + sovCortex(uint64(l))
	}
	return n
}

// Equal implements proto.Equaler.
func (bs *LabelAdapter) Equal(other LabelAdapter) bool {
	return bs.Name == other.Name && bs.Value == other.Value
}

// Compare implements proto.Comparer.
func (bs *LabelAdapter) Compare(other LabelAdapter) int {
	if c := strings.Compare(bs.Name, other.Name); c != 0 {
		return c
	}
	return strings.Compare(bs.Value, other.Value)
}

// PreallocTimeseriesSliceFromPool retrieves a slice of PreallocTimeseries from a sync.Pool.
// ReuseSlice should be called once done.
func PreallocTimeseriesSliceFromPool() []PreallocTimeseries {
	return slicePool.Get().([]PreallocTimeseries)
}

// ReuseSlice puts the slice back into a sync.Pool for reuse.
func ReuseSlice(ts []PreallocTimeseries) {
	for i := range ts {
		ReuseTimeseries(ts[i].TimeSeries)
	}

	slicePool.Put(ts[:0]) //nolint:staticcheck //see comment on slicePool for more details
}

// TimeseriesFromPool retrieves a pointer to a TimeSeries from a sync.Pool.
// ReuseTimeseries should be called once done, unless ReuseSlice was called on the slice that contains this TimeSeries.
func TimeseriesFromPool() *TimeSeries {
	return timeSeriesPool.Get().(*TimeSeries)
}

// ReuseTimeseries puts the timeseries back into a sync.Pool for reuse.
func ReuseTimeseries(ts *TimeSeries) {
	// Name and Value may point into a large gRPC buffer, so clear the reference to allow GC
	for i := 0; i < len(ts.Labels); i++ {
		ts.Labels[i].Name = ""
		ts.Labels[i].Value = ""
	}
	ts.Labels = ts.Labels[:0]
	ts.Samples = ts.Samples[:0]
	// Name and Value may point into a large gRPC buffer, so clear the reference in each exemplar to allow GC
	for i := range ts.Exemplars {
		for j := range ts.Exemplars[i].Labels {
			ts.Exemplars[i].Labels[j].Name = ""
			ts.Exemplars[i].Labels[j].Value = ""
		}
	}
	ts.Exemplars = ts.Exemplars[:0]
	timeSeriesPool.Put(ts)
}
