package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// DefaultMaxDecodedSize is the default maximum decoded (uncompressed) size
// allowed by Proto.Decode. Ring and HA-tracker membership state is orders of
// magnitude smaller than this, and bounding the decoded size prevents a
// malicious gossip peer from forcing a multi-gigabyte heap allocation via a
// snappy decompression bomb (a short payload whose varint header declares an
// enormous uncompressed length).
const DefaultMaxDecodedSize = 32 << 20 // 32 MiB

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
	id             string
	factory        func() proto.Message
	maxDecodedSize int
}

// NewProtoCodec returns a Proto codec using DefaultMaxDecodedSize as the
// upper bound for the snappy-declared uncompressed length.
func NewProtoCodec(id string, factory func() proto.Message) Proto {
	return Proto{id: id, factory: factory, maxDecodedSize: DefaultMaxDecodedSize}
}

// NewProtoCodecWithMaxDecodedSize returns a Proto codec that will reject
// payloads whose snappy-declared uncompressed length exceeds maxDecodedSize.
// A non-positive value disables the limit (not recommended on gossip paths).
func NewProtoCodecWithMaxDecodedSize(id string, factory func() proto.Message, maxDecodedSize int) Proto {
	return Proto{id: id, factory: factory, maxDecodedSize: maxDecodedSize}
}

func (p Proto) CodecID() string {
	return p.id
}

// Decode implements Codec.
//
// The declared uncompressed length is validated BEFORE calling snappy.Decode,
// because snappy.Decode allocates a buffer of that length using the varint
// from the input before validating the rest of the stream. A 5-byte attacker
// controlled header can therefore force a ~4 GiB allocation. Bounding the
// declared size here closes that OOM vector.
func (p Proto) Decode(bytes []byte) (interface{}, error) {
	dLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if p.maxDecodedSize > 0 && dLen > p.maxDecodedSize {
		return nil, fmt.Errorf("snappy payload too large: declared decoded size %d exceeds limit %d", dLen, p.maxDecodedSize)
	}

	out := p.factory()
	// Pass a zero-length buffer with capacity dLen so snappy reuses it instead
	// of allocating a new slice. dLen is bounded by the check above.
	plain, err := snappy.Decode(make([]byte, 0, dLen), bytes)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(plain, out); err != nil {
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
