package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is the maximum decoded payload size (in bytes) accepted by
// Proto.Decode. It bounds the heap allocation the snappy block decoder is
// allowed to make from an attacker-controlled varint length header, preventing
// a decompression bomb against callers that feed untrusted bytes into the
// codec (notably the memberlist gossip path). The value is comfortably larger
// than any legitimate Cortex ring descriptor, but small enough that an
// attacker cannot drive a multi-GiB allocation per message.
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
func (p Proto) Decode(data []byte) (interface{}, error) {
	out := p.factory()
	// Validate the declared decoded length from the snappy header before
	// allocating the output buffer. snappy.Decode would otherwise call
	// make([]byte, dLen) with dLen taken verbatim from the caller-supplied
	// varint (bounded only by ~4 GiB), enabling a decompression bomb.
	size, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, err
	}
	if size > MaxDecodedSize {
		return nil, fmt.Errorf("snappy-encoded payload decoded size %d exceeds maximum %d", size, MaxDecodedSize)
	}
	decoded, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(decoded, out); err != nil {
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
