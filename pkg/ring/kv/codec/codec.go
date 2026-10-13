package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is the maximum allowed size, in bytes, of a snappy-decoded
// value handed to Proto.Decode. It bounds the allocation performed by
// snappy.Decode (which allocates make([]byte, dLen) from the declared decoded
// length in the attacker-controlled block header before validating the body),
// to protect against decompression-bomb inputs delivered via the memberlist
// gossip transport or other KV backends. 64 MiB is well above legitimate
// ring/HA-tracker payloads and well below the 4 GiB that an unbounded varint
// header would otherwise request.
const MaxDecodedSize = 64 * 1024 * 1024

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
	// Bound the declared decoded size before calling snappy.Decode, which
	// otherwise allocates make([]byte, dLen) from the attacker-supplied
	// length header prior to validating the compressed body. Without this
	// guard, a ~30-byte input with a varint claiming ~4 GiB would force a
	// multi-gigabyte allocation. See MaxDecodedSize for rationale.
	decodedLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if decodedLen > MaxDecodedSize {
		return nil, fmt.Errorf("snappy-decoded size %d exceeds maximum allowed %d", decodedLen, MaxDecodedSize)
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
