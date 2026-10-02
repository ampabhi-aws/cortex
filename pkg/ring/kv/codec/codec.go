package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// maxDecodedSize caps the size (in bytes) of a snappy-compressed KV value
// that Proto.Decode is willing to decompress. It defends against a
// decompression bomb on the gossip/memberlist KV path, where the Decode
// input is attacker-controlled network bytes: without this cap the
// vendored snappy library allocates make([]byte, declaredLen) up to
// 0xffffffff (4 GiB) before validating the compressed body, which an
// unauthenticated peer can trigger with a ~60-byte packet.
//
// 128 MiB is well above the realistic size of any Cortex ring descriptor
// or HA-tracker replica descriptor and comfortably below memberlist's
// own 20 MiB push/pull cap applied at the stream level, so legitimate
// traffic is never affected.
const maxDecodedSize = 128 * 1024 * 1024

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
	// Bound the compressed input: reject oversized payloads outright so we
	// do not even look at their snappy header.
	if len(bytes) > maxDecodedSize {
		return nil, fmt.Errorf("snappy-compressed value is %d bytes, exceeds the %d bytes limit", len(bytes), maxDecodedSize)
	}
	// Bound the declared decompressed length BEFORE calling snappy.Decode,
	// because snappy.Decode performs make([]byte, declaredLen) prior to
	// validating the compressed body. Without this check an attacker can
	// declare up to 0xffffffff bytes (4 GiB) in the snappy header and force
	// a large heap allocation on this process.
	decodedLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if decodedLen > maxDecodedSize {
		return nil, fmt.Errorf("snappy-decoded value is %d bytes, exceeds the %d bytes limit", decodedLen, maxDecodedSize)
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
