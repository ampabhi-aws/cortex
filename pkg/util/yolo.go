package util

import (
	"reflect"
	"unsafe"
)

// YoloBuf returns a []byte that aliases the backing bytes of s without
// copying. The returned slice has cap == len; it must be treated as
// read-only -- writing through it (directly, via append within cap, or
// via a full-slice reslice) is undefined behaviour because Go string
// bytes are immutable and may live in read-only memory.
//
// The naive construct *((*[]byte)(unsafe.Pointer(&s))) is unsafe: a Go
// string header is 2 words (data, len) but a slice header is 3 words
// (data, len, cap), so the dereference reads one word past the string
// header and installs that unrelated word as the slice capacity. The
// resulting slice violates the 0 <= len <= cap invariant and lets any
// downstream append/reslice read or write out of bounds. We build the
// slice header explicitly so that cap == len.
func YoloBuf(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var b []byte
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}
