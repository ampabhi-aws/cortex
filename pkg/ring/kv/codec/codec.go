package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// maxDecodedProtoSize bounds the size (in bytes) of the buffer we are willing to
// allocate while decompressing a snappy-encoded KV payload. snappy allocates
// make([]byte, dLen) using the attacker-declared varint length BEFORE the body
// is validated, so without this guard a tiny packet can request a multi-GiB
// allocation. Legitimate ring descriptors are far smaller than 128 MiB, so this
// gives generous headroom while keeping the attacker-controlled allocation
// bounded.
const maxDecodedProtoSize = 128 * 1024 * 1024

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
	// snappy.Decode allocates a destination buffer sized by the attacker-declared
	// varint length in the compressed stream before any body validation. Pre-check
	// the declared length so a malicious peer cannot drive us into a multi-GiB
	// allocation with a tiny input.
	dLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if dLen < 0 || dLen > maxDecodedProtoSize {
		return nil, fmt.Errorf("snappy-decoded value too large: %d bytes (max %d)", dLen, maxDecodedProtoSize)
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
