package util

import (
	"reflect"
	"unsafe"
)

// YoloBuf returns a []byte that aliases the backing storage of the given string.
// The returned slice MUST NOT be mutated or appended to: the underlying bytes
// are owned by the string (which may live in read-only memory) and the slice's
// capacity is deliberately clamped to its length. This helper exists to avoid
// an allocation when passing strings to hashers (e.g. md5/xxhash) that only
// read the first len(b) bytes.
func YoloBuf(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	// Construct a slice header with Cap == Len so cap(b) is well-defined and
	// no out-of-bounds read occurs (dereferencing *[]byte over &s would read
	// a third word past the string header).
	var b []byte
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}
