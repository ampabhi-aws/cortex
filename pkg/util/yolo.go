package util

import (
	"reflect"
	"unsafe"
)

// YoloBuf returns a []byte that aliases the backing array of s without
// copying. The returned slice shares memory with the (immutable) string s
// and MUST NOT be written to, appended to, or resliced beyond len(s).
// Doing so would corrupt the string's backing storage or read memory
// outside the string's allocation.
//
// Implementation note: a Go string header is two words (data, len) while a
// slice header is three words (data, len, cap). We therefore cannot simply
// reinterpret &s as a *[]byte -- that would read an undefined third word
// (the slice's cap) from whatever happens to follow the string header in
// the caller's frame. Instead we construct the slice header explicitly and
// set cap = len(s) so the result is a well-formed slice.
func YoloBuf(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	hdr.Data = (*reflect.StringHeader)(unsafe.Pointer(&s)).Data
	hdr.Len = len(s)
	hdr.Cap = len(s)
	return b
}
