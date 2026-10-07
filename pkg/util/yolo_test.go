package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestYoloBuf(t *testing.T) {
	s := YoloBuf("hello world")

	require.Equal(t, []byte("hello world"), s)
	// The returned slice must have cap == len so that any accidental
	// re-slice or append stays within the string's backing array.
	require.Equal(t, len(s), cap(s))
}

func TestYoloBuf_Empty(t *testing.T) {
	require.Nil(t, YoloBuf(""))
}
