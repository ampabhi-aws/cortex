package util

import (
	"reflect"
	"unsafe"
)

// YoloBuf returns a read-only view of s with cap == len. Callers MUST NOT
// write to or append to the returned slice: it aliases immutable string data.
//
// The previous implementation reinterpreted the address of a 2-word string
// header as a 3-word slice header, which read the slice's capacity from
// unrelated adjacent memory (undefined behaviour per unsafe.Pointer rules).
// This version constructs a correctly sized slice header with cap == len,
// so a hypothetical caller that re-slices or appends cannot read/write past
// the string's backing array through indeterminate capacity.
func YoloBuf(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b)) //nolint:govet
	hdr.Data = (*reflect.StringHeader)(unsafe.Pointer(&s)).Data
	hdr.Len = len(s)
	hdr.Cap = len(s)
	return b
}
