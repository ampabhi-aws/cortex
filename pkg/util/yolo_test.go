package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestYoloBuf(t *testing.T) {
	s := YoloBuf("hello world")

	require.Equal(t, []byte("hello world"), s)
	require.Equal(t, len(s), cap(s), "YoloBuf must return a slice with cap == len")
}
