package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is the hard upper bound (in bytes) on the length of a
// snappy-decoded payload accepted by Proto.Decode. The vendored snappy
// implementation allocates the destination buffer based on the varint header
// in the input *before* validating that the input actually contains that much
// data, so an attacker-controlled ~10 byte payload whose header declares a
// 4 GiB decoded length can force a multi-GiB allocation and OOM-kill the
// process. Ring/KV state is small in practice (ring descriptors, HA tracker
// entries, etc.), so a conservative 128 MiB cap preserves legitimate traffic
// while blocking decompression bombs. Values whose declared decoded length
// exceeds this cap are rejected without allocating.
const MaxDecodedSize = 128 * 1024 * 1024

// Codec allows KV clients to serialise and deserialise values.
type Codec interface {
	Decode([]byte) (interface{}, error)
	Encode(interface{}) ([]byte, error)

	// CodecID is a short identifier to communicate what codec should be used to decode the value.
	// Once in use, this should be stable to avoid confusing other clients.
	CodecID() string
}

// Proto is a Codec for proto/snappy
type Proto struct {
	id      string
	factory func() proto.Message
}

func NewProtoCodec(id string, factory func() proto.Message) Proto {
	return Proto{id: id, factory: factory}
}

func (p Proto) CodecID() string {
	return p.id
}

// Decode implements Codec
func (p Proto) Decode(bytes []byte) (interface{}, error) {
	out := p.factory()
	// Bound the decoded length before snappy.Decode allocates the output
	// buffer: snappy reads the declared length from the input's varint header
	// and does `make([]byte, dLen)` with no sanity check beyond dLen <=
	// 0xffffffff. Rejecting oversized headers up front turns a decompression
	// bomb into a cheap error instead of a multi-GiB allocation.
	decodedLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if decodedLen > MaxDecodedSize {
		return nil, fmt.Errorf("snappy-decoded value too large: %d bytes (max %d)", decodedLen, MaxDecodedSize)
	}
	bytes, err = snappy.Decode(nil, bytes)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(bytes, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Encode implements Codec
func (p Proto) Encode(msg interface{}) ([]byte, error) {
	bytes, err := proto.Marshal(msg.(proto.Message))
	if err != nil {
		return nil, err
	}
	return snappy.Encode(nil, bytes), nil
}

// String is a code for strings.
type String struct{}

func (String) CodecID() string {
	return "string"
}

// Decode implements Codec.
func (String) Decode(bytes []byte) (interface{}, error) {
	return string(bytes), nil
}

// Encode implements Codec.
func (String) Encode(msg interface{}) ([]byte, error) {
	return []byte(msg.(string)), nil
}
