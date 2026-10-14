package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is the maximum allowed size, in bytes, of the uncompressed
// payload the Proto codec is willing to decode. It bounds the amount of memory
// that a snappy decompression step can allocate up front and protects against
// decompression-bomb inputs received from (potentially untrusted) memberlist
// peers. Callers that need a smaller or larger limit may override this value
// at process startup; it is intentionally a var rather than a constant so
// tests and operators can tune it, but the default is deliberately generous
// enough for all legitimate ring/HA-tracker payloads and small enough to
// prevent OOM in a single Decode call.
//
// 10 MiB is consistent with the memberlist UDPBufferSize used by the
// cortex KV layer (pkg/ring/kv/memberlist/memberlist_client.go) and with
// the maxRecvMsgSize bound used on the HTTP ingest path.
var MaxDecodedSize = 10 * 1024 * 1024

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

// Decode implements Codec.
//
// Decode is defensive about its input because its callers (notably the
// memberlist gossip delegate) may hand it attacker-controlled bytes:
//
//  1. It inspects the snappy header via snappy.DecodedLen and rejects any
//     payload whose declared uncompressed size exceeds MaxDecodedSize,
//     before any large buffer is allocated. The vendored snappy would
//     otherwise allocate make([]byte, dLen) with dLen read from the
//     attacker-supplied varint (bounded only by 0xffffffff), enabling a
//     ~10-byte input to force a multi-GiB allocation.
//  2. It also caps the size of the compressed input itself at
//     MaxDecodedSize, so that a legitimately-sized decoded payload cannot
//     be padded with arbitrarily large compressed junk.
//  3. It decodes into a pre-sized buffer of exactly the expected length so
//     the resulting slice cannot grow beyond the declared (and already
//     bounded) size.
func (p Proto) Decode(bytes []byte) (interface{}, error) {
	out := p.factory()

	maxSize := MaxDecodedSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}

	if len(bytes) > maxSize {
		return nil, fmt.Errorf("compressed payload size %d exceeds maximum allowed size %d", len(bytes), maxSize)
	}

	decodedLen, err := snappy.DecodedLen(bytes)
	if err != nil {
		return nil, err
	}
	if decodedLen < 0 || decodedLen > maxSize {
		return nil, fmt.Errorf("decoded payload size %d exceeds maximum allowed size %d", decodedLen, maxSize)
	}

	// Decode into a destination buffer sized to the (already-bounded) declared
	// length rather than passing nil, so snappy.Decode cannot allocate more
	// than maxSize bytes even if the header is inconsistent with the body.
	dst := make([]byte, decodedLen)
	decoded, err := snappy.Decode(dst, bytes)
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
