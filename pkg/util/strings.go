package util

import "unsafe"

// StringsContain returns true if the search value is within the list of input values.
func StringsContain(values []string, search string) bool {
	for _, v := range values {
		if search == v {
			return true
		}
	}

	return false
}

// StringsMap returns a map where keys are input values.
func StringsMap(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// StringsClone returns a copy input s
// see: https://github.com/golang/go/blob/master/src/strings/clone.go
func StringsClone(s string) string {
	b := make([]byte, len(s))
	copy(b, s)
	return *(*string)(unsafe.Pointer(&b))
}

// TruncateString returns s truncated to at most maxLen bytes. If s is longer
// than maxLen, the returned string is clipped and an ellipsis marker is
// appended so callers can tell the value was truncated. This is intended for
// log fields and error messages that may embed attacker-controlled strings;
// the caller is responsible for ensuring maxLen is reasonable (>= 8).
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	const marker = "...[truncated]"
	if maxLen <= len(marker) {
		return s[:maxLen]
	}
	return s[:maxLen-len(marker)] + marker
}
