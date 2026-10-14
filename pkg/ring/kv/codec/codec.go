package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// maxDecodedSize is the hard cap on the uncompressed size (in bytes) of a
// snappy-encoded value accepted by Proto.Decode. The declared uncompressed
// length in the snappy block header is attacker-controlled and bounded only
// by snappy's own 4 GiB limit, so without an upper bound a tiny (a few bytes)
// payload can force snappy.Decode to allocate multi-gigabyte buffers
// (decompression bomb). 128 MiB is well above the size of any realistic
// value put into our KV stores (ring descriptors, lifecycler state, etc.)
// while still preventing single-request heap exhaustion.
const maxDecodedSize = 128 << 20 // 128 MiB

// maxEncodedSize is a sanity cap on the encoded (compressed) payload size
// before we even look at the declared uncompressed length. This keeps us
// from being handed arbitrarily large encoded buffers in the first place.
const maxEncodedSize = 128 << 20 // 128 MiB

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
	// Bound the input before handing it to snappy. snappy.Decode reads the
	// uncompressed length from the payload's varint header and allocates it
	// in one shot before decompressing anything, so an attacker-controlled
	// value can force multi-GiB allocations. Reject oversized encoded
	// payloads and oversized declared uncompressed lengths up front.
	if len(bytes) > maxEncodedSize {
		return nil, fmt.Errorf("encoded value too large: %d bytes (max %d)", len(bytes), maxEncodedSize)
	}
	decodedLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if decodedLen < 0 || decodedLen > maxDecodedSize {
		return nil, fmt.Errorf("decoded value too large: %d bytes (max %d)", decodedLen, maxDecodedSize)
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
