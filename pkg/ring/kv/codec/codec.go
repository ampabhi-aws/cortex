package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// DefaultMaxDecodedSize is the default upper bound (in bytes) on the result of
// snappy-decompressing a Proto codec payload. It applies when a Proto codec is
// used without an explicit limit (e.g. non-memberlist KV backends). It is
// intentionally large enough for realistic KV values and small enough to
// prevent a single untrusted frame from triggering multi-gigabyte allocations.
const DefaultMaxDecodedSize = 64 * 1024 * 1024 // 64 MiB

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

	// maxDecodedSize is the maximum size, in bytes, of the snappy-decoded payload
	// Decode is willing to allocate. A value of 0 means "use DefaultMaxDecodedSize".
	// A negative value disables the check entirely (not recommended for untrusted input).
	maxDecodedSize int
}

func NewProtoCodec(id string, factory func() proto.Message) Proto {
	return Proto{id: id, factory: factory}
}

// WithMaxDecodedSize returns a copy of the Proto codec that refuses to allocate
// more than maxBytes to decode a single value. Pass a positive value to set a
// limit, 0 to use DefaultMaxDecodedSize, or a negative value to disable the
// check (not recommended for untrusted input).
func (p Proto) WithMaxDecodedSize(maxBytes int) Proto {
	p.maxDecodedSize = maxBytes
	return p
}

// MaxDecodedSize returns the effective maximum decoded size enforced by Decode,
// or <= 0 if the check is disabled.
func (p Proto) MaxDecodedSize() int {
	if p.maxDecodedSize == 0 {
		return DefaultMaxDecodedSize
	}
	return p.maxDecodedSize
}

func (p Proto) CodecID() string {
	return p.id
}

// Decode implements Codec. Before allocating the output buffer for
// snappy-decompression, Decode inspects the varint length prefix in the input
// and refuses payloads whose claimed decoded length exceeds the configured
// maximum (see WithMaxDecodedSize / DefaultMaxDecodedSize). This prevents a
// tiny attacker-controlled snappy frame from causing a multi-GiB allocation
// inside snappy.Decode.
func (p Proto) Decode(bytes []byte) (interface{}, error) {
	maxSize := p.MaxDecodedSize()
	if maxSize > 0 {
		dLen, err := snappy.DecodedLen(bytes)
		if err != nil {
			return nil, err
		}
		if dLen > maxSize {
			return nil, fmt.Errorf("snappy decoded length %d exceeds maximum %d", dLen, maxSize)
		}
	}
	out := p.factory()
	bytes, err := snappy.Decode(nil, bytes)
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
