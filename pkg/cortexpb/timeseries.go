package cortexpb

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"unsafe"

	"github.com/prometheus/prometheus/model/labels"
)

var (
	expectedTimeseries         = 100
	expectedLabels             = 20
	expectedSamplesPerSeries   = 10
	expectedExemplarsPerSeries = 1

	// maxTimeseriesPerRequest bounds the number of Timeseries elements that may
	// appear in a single WriteRequest. It defends against protobuf object-inflation
	// bombs where a tiny snappy-compressed body decodes into tens of millions of
	// repeated (often empty) Timeseries elements, each of which would otherwise
	// cost ~1 KB of heap via the pooled allocator. Configurable through the
	// -distributor.max-timeseries-per-request flag; 0 disables the limit (not
	// recommended).
	maxTimeseriesPerRequest = 100000

	// ErrTooManyTimeseries is returned by PreallocWriteRequest.Unmarshal when a
	// request carries more than maxTimeseriesPerRequest Timeseries elements.
	ErrTooManyTimeseries = fmt.Errorf("too many timeseries in write request")

	// errEmptyTimeseries is returned from PreallocTimeseries.Unmarshal when the
	// element is degenerate (no labels and no samples/exemplars on the wire).
	// We treat it as a short-circuit sentinel so we never allocate a pooled
	// TimeSeries for it.
	errEmptyTimeseries = fmt.Errorf("empty timeseries in write request")

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

	// timeSeriesPool stores *TimeSeries with nil Labels/Samples/Exemplars slices.
	// Keeping the pooled object lazy means an empty wire element costs ~80 B
	// (the TimeSeries struct) instead of ~1 KB of eagerly allocated slice
	// backing arrays. The generated TimeSeries.Unmarshal appends into these
	// fields, which is a no-op on nil slices, so correctness is preserved for
	// well-formed requests and the slices grow to the size actually required
	// by the bytes on the wire.
	timeSeriesPool = sync.Pool{
		New: func() interface{} {
			return &TimeSeries{}
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
	f.IntVar(&maxTimeseriesPerRequest, "distributor.max-timeseries-per-request", maxTimeseriesPerRequest, "Maximum number of timeseries elements allowed in a single remote_write request. Protects the distributor from protobuf object-inflation bombs that decode into millions of empty Timeseries elements. 0 disables the limit (not recommended).")
}

// PreallocWriteRequest is a WriteRequest which preallocs slices on Unmarshal.
type PreallocWriteRequest struct {
	WriteRequest
}

// Unmarshal implements proto.Message.
//
// Before invoking the generated unmarshaler, we do a cheap single-pass scan of
// the protobuf wire bytes and count how many Timeseries elements (field 1,
// wire type 2) are present. If the count exceeds maxTimeseriesPerRequest we
// bail out immediately, so an object-inflation bomb (tens of millions of
// repeated 2-byte empty elements) never triggers any heap allocation for its
// backing TimeSeries objects or for growing the Timeseries backing array.
func (p *PreallocWriteRequest) Unmarshal(dAtA []byte) error {
	if maxTimeseriesPerRequest > 0 {
		if n, err := countTimeseries(dAtA, maxTimeseriesPerRequest); err != nil {
			return err
		} else if n > maxTimeseriesPerRequest {
			return fmt.Errorf("%w: >%d (limit: %d)", ErrTooManyTimeseries, maxTimeseriesPerRequest, maxTimeseriesPerRequest)
		}
	}
	p.Timeseries = PreallocTimeseriesSliceFromPool()
	if err := p.WriteRequest.Unmarshal(dAtA); err != nil {
		return err
	}
	if maxTimeseriesPerRequest > 0 && len(p.Timeseries) > maxTimeseriesPerRequest {
		return fmt.Errorf("%w: %d (limit: %d)", ErrTooManyTimeseries, len(p.Timeseries), maxTimeseriesPerRequest)
	}
	return nil
}

// countTimeseries walks the top-level fields of a WriteRequest wire-format
// message and counts how many Timeseries elements (field tag 1, wire type 2)
// it contains. It stops as soon as the count exceeds limit (returning
// limit+1) so a malicious payload with billions of elements is rejected
// without a full linear scan being completed. Only the top level is walked;
// nested message bodies are skipped by their length prefix without being
// descended into, so this is O(number of top-level fields), not O(bytes).
// Any wire-format error is returned to the caller so the generated
// unmarshaler is never asked to parse clearly malformed input.
func countTimeseries(dAtA []byte, limit int) (int, error) {
	l := len(dAtA)
	iNdEx := 0
	count := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return count, ErrIntOverflowCortex
			}
			if iNdEx >= l {
				return count, io.ErrUnexpectedEOF
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
		if fieldNum == 1 && wireType == 2 {
			count++
			if count > limit {
				return count, nil
			}
		}
		switch wireType {
		case 0: // varint
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return count, ErrIntOverflowCortex
				}
				if iNdEx >= l {
					return count, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				if b < 0x80 {
					break
				}
			}
		case 1: // fixed64
			if iNdEx+8 > l {
				return count, io.ErrUnexpectedEOF
			}
			iNdEx += 8
		case 2: // length-delimited
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return count, ErrIntOverflowCortex
				}
				if iNdEx >= l {
					return count, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return count, ErrInvalidLengthCortex
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 || postIndex > l {
				return count, io.ErrUnexpectedEOF
			}
			iNdEx = postIndex
		case 5: // fixed32
			if iNdEx+4 > l {
				return count, io.ErrUnexpectedEOF
			}
			iNdEx += 4
		default:
			// Delegate unknown / group wire types to the generated unmarshaler
			// by stopping the pre-scan here. We return the count collected so
			// far; the generated code will produce the appropriate error.
			return count, nil
		}
	}
	return count, nil
}

// PreallocTimeseries is a TimeSeries which preallocs slices on Unmarshal.
type PreallocTimeseries struct {
	*TimeSeries
}

// Unmarshal implements proto.Message.
//
// Degenerate elements (empty wire body, i.e. no labels and no samples) are
// rejected cheaply BEFORE a pooled *TimeSeries is materialised. This blocks
// protobuf object-inflation bombs that send a repeated 2-byte pattern
// (0x0a 0x00) and would otherwise cost ~1 KB of heap per 2 wire bytes.
func (p *PreallocTimeseries) Unmarshal(dAtA []byte) error {
	if len(dAtA) == 0 {
		return errEmptyTimeseries
	}
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
		if ts[i].TimeSeries != nil {
			ReuseTimeseries(ts[i].TimeSeries)
		}
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
	if ts == nil {
		return
	}
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
