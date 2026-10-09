package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is an upper bound on the uncompressed size of a single
// snappy-encoded value accepted by Proto.Decode. It is deliberately set well
// above any legitimate ring/KV payload so that honest producers are never
// rejected, while preventing an attacker-declared decompressed length from
// forcing an unbounded allocation (CWE-770). The vendored golang/snappy
// library allocates the destination buffer from the declared length *before*
// validating the body, so this limit must be enforced before calling
// snappy.Decode.
const MaxDecodedSize = 32 << 20 // 32 MiB

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
	// Bound the decompressed size before allocating. snappy.Decode allocates a
	// buffer sized by the attacker-declared uncompressed length header (up to
	// 0xFFFFFFFF) before validating the body, so this pre-check is required to
	// prevent remote OOM via unauthenticated gossip (CWE-770).
	n, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, err
	}
	if n > MaxDecodedSize {
		return nil, fmt.Errorf("snappy payload too large: declared %d bytes, limit %d", n, MaxDecodedSize)
	}
	out := p.factory()
	// Allocate the destination with the already-validated declared length so
	// snappy.Decode cannot grow it past our limit.
	plain, err := snappy.Decode(make([]byte, 0, n), data)
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
