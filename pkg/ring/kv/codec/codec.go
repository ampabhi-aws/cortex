package codec

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
)

// MaxDecodedSize is the maximum uncompressed size (in bytes) that Proto.Decode
// will accept. The ring and HA tracker Desc messages carry per-instance state
// for an entire cluster, but 64 MiB is still a generous upper bound and keeps
// a hostile peer from forcing a multi-gigabyte allocation on the gossip path.
// See the "Snappy decompression bomb" advisory for background.
const MaxDecodedSize = 64 << 20

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
// Decode validates the attacker-controllable uncompressed length declared in
// the snappy header before allocating the destination buffer, so a tiny
// compressed payload cannot force a multi-gigabyte heap allocation (a
// decompression bomb against the memberlist gossip listener).
func (p Proto) Decode(data []byte) (interface{}, error) {
	dLen, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, err
	}
	if dLen > MaxDecodedSize {
		return nil, fmt.Errorf("snappy-decoded value too large: %d > %d", dLen, MaxDecodedSize)
	}
	out := p.factory()
	decoded, err := snappy.Decode(make([]byte, 0, dLen), data)
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
