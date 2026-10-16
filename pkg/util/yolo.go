package util

import "unsafe"

// YoloBuf returns a []byte that aliases the backing array of s without
// copying. The returned slice is READ-ONLY: callers must never append to it,
// write through it, or re-slice it beyond len (e.g. b[:cap(b)]), because the
// backing storage is immutable string memory. It is intended solely for
// read-only consumers such as hash.Hash.Write.
//
// The slice header is constructed with an explicit capacity equal to len(s)
// so that cap(b) == len(b); earlier revisions reinterpreted the 2-word
// string header as a 3-word slice header, which left cap undefined.
func YoloBuf(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}
