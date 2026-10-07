package util

import "unsafe"

// YoloBuf returns a []byte that aliases the backing storage of s without
// copying. The returned slice has len == cap == len(s) and MUST be treated
// as read-only: callers MUST NOT write to it and MUST NOT append to it,
// since the underlying bytes may live in read-only memory or alias a Go
// string header. It is the caller's responsibility to ensure the slice
// does not outlive s.
//
// The previous implementation was unsound: a Go string header is 2 words
// while a slice header is 3 words, so cap() was read from adjacent stack
// memory and could be arbitrarily large. This form explicitly supplies
// Cap == len(s).
func YoloBuf(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&struct {
		string
		Cap int
	}{s, len(s)}))
}
