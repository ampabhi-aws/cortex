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

// ErrTooManyTimeseries is returned by PreallocWriteRequest.Unmarshal when a
// remote-write request contains more timeseries than the configured cap. It is
// used to abort decoding of a parse-bomb request before the amplified objects
// are retained and before downstream validation runs.
var ErrTooManyTimeseries = errors.New("too many timeseries in write request")

// ErrTooManyMetadata is the companion of ErrTooManyTimeseries for the
// metric-metadata field of a WriteRequest.
var ErrTooManyMetadata = errors.New("too many metric metadata in write request")

var (
	expectedTimeseries         = 100
	expectedLabels             = 20
	expectedSamplesPerSeries   = 10
	expectedExemplarsPerSeries = 1

	// maxTimeseriesPerRequest caps the number of TimeSeries decoded from a
	// single remote-write WriteRequest, independent of the raw-byte limit.
	// It defends against protobuf parse bombs where a tiny snappy-compressed
	// body expands into tens of millions of pooled TimeSeries structs
	// (~928 B each) and OOM-kills the distributor. 0 = unlimited (legacy
	// behaviour).
	maxTimeseriesPerRequest = 0

	// maxMetadataPerRequest is the metadata-field counterpart of
	// maxTimeseriesPerRequest. 0 = unlimited.
	maxMetadataPerRequest = 0

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
	f.IntVar(&maxTimeseriesPerRequest, "ingester-client.max-timeseries-per-request", maxTimeseriesPerRequest, "Hard cap on the number of timeseries that may be decoded from a single remote-write request. Enforced inside the WriteRequest unmarshaller before any validation or rate-limiting, to defend against protobuf parse bombs that otherwise amplify a small compressed body into millions of pooled TimeSeries allocations. 0 = unlimited.")
	f.IntVar(&maxMetadataPerRequest, "ingester-client.max-metadata-per-request", maxMetadataPerRequest, "Hard cap on the number of metric metadata entries that may be decoded from a single remote-write request. Enforced inside the WriteRequest unmarshaller before any validation. 0 = unlimited.")
}

// SetMaxTimeseriesPerRequest overrides the per-request timeseries cap at
// runtime. It is intended for tests and for callers that configure the limit
// outside of the flag set (e.g. YAML-only wiring). A non-positive value
// disables the cap.
func SetMaxTimeseriesPerRequest(n int) {
	if n < 0 {
		n = 0
	}
	maxTimeseriesPerRequest = n
}

// MaxTimeseriesPerRequest returns the currently configured cap. 0 means
// unlimited.
func MaxTimeseriesPerRequest() int {
	return maxTimeseriesPerRequest
}

// PreallocWriteRequest is a WriteRequest which preallocs slices on Unmarshal.
type PreallocWriteRequest struct {
	WriteRequest
}

// Unmarshal implements proto.Message.
//
// After the generated unmarshaller completes we enforce
// maxTimeseriesPerRequest / maxMetadataPerRequest as a backstop against
// protobuf parse-bomb requests. If the cap is exceeded the pooled
// TimeSeries objects are returned to the pool and an error is reported
// before the request can propagate into the distributor pipeline.
func (p *PreallocWriteRequest) Unmarshal(dAtA []byte) error {
	p.Timeseries = PreallocTimeseriesSliceFromPool()
	if err := p.WriteRequest.Unmarshal(dAtA); err != nil {
		return err
	}
	if maxTimeseriesPerRequest > 0 && len(p.Timeseries) > maxTimeseriesPerRequest {
		ReuseSlice(p.Timeseries)
		p.Timeseries = nil
		return ErrTooManyTimeseries
	}
	if maxMetadataPerRequest > 0 && len(p.Metadata) > maxMetadataPerRequest {
		ReuseSlice(p.Timeseries)
		p.Timeseries = nil
		p.Metadata = nil
		return ErrTooManyMetadata
	}
	return nil
}

// PreallocTimeseries is a TimeSeries which preallocs slices on Unmarshal.
type PreallocTimeseries struct {
	*TimeSeries
}

// Unmarshal implements proto.Message.
func (p *PreallocTimeseries) Unmarshal(dAtA []byte) error {
	p.TimeSeries = TimeseriesFromPool()
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
