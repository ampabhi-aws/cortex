package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// maxDecodedSize caps the amount of memory the proto/snappy codec is willing
// to allocate for a single decoded value. Without this cap an attacker-chosen
// snappy header varint (up to 0xffffffff) drives make([]byte, dLen) inside
// snappy.Decode and can force a ~4 GiB allocation from a ~60-byte input.
const maxDecodedSize = 64 * 1024 * 1024

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
	// Guard the decoded-size varint before snappy.Decode allocates its
	// destination buffer. snappy accepts a declared length up to 0xffffffff
	// and will allocate make([]byte, dLen) before validating the body, so
	// without this check a tiny attacker-controlled message can force a
	// multi-GiB allocation.
	n, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if n > maxDecodedSize {
		return nil, fmt.Errorf("snappy: decoded value too large: %d bytes (max %d)", n, maxDecodedSize)
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
