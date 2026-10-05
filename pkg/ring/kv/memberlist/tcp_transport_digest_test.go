package memberlist

import (
	"bytes"
	"crypto/md5"
	"net"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestTCPTransport_BadDigestIsDropped verifies that a packet whose trailing
// MD5 digest does not match the recomputed digest is never delivered to
// PacketCh. Regression test for a missing return after the digest check in
// TCPTransport.handleConnection.
func TestTCPTransport_BadDigestIsDropped(t *testing.T) {
	cfg := TCPTransportConfig{}
	flagext.DefaultValues(&cfg)
	cfg.BindAddrs = []string{"127.0.0.1"}
	cfg.BindPort = 0

	tr, err := NewTCPTransport(cfg, log.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Shutdown() })

	c, s := net.Pipe()
	go tr.handleConnection(s)

	remote := "1.2.3.4:1"
	payload := []byte("CORRUPTED")

	// Write header (msg type + addr length), address, payload, and a
	// deliberately wrong digest.
	_, err = c.Write([]byte{byte(packet), byte(len(remote))})
	require.NoError(t, err)
	_, err = c.Write([]byte(remote))
	require.NoError(t, err)
	_, err = c.Write(payload)
	require.NoError(t, err)
	_, err = c.Write(bytes.Repeat([]byte{0xFF}, md5.Size))
	require.NoError(t, err)
	require.NoError(t, c.Close())

	select {
	case p := <-tr.PacketCh():
		t.Fatalf("packet with bad digest was delivered: %q", p.Buf)
	case <-time.After(500 * time.Millisecond):
		// expected: nothing delivered
	}
}

// TestTCPTransport_GoodDigestIsDelivered is a positive control: a packet with
// a correct digest should be delivered to PacketCh.
func TestTCPTransport_GoodDigestIsDelivered(t *testing.T) {
	cfg := TCPTransportConfig{}
	flagext.DefaultValues(&cfg)
	cfg.BindAddrs = []string{"127.0.0.1"}
	cfg.BindPort = 0

	tr, err := NewTCPTransport(cfg, log.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Shutdown() })

	c, s := net.Pipe()
	go tr.handleConnection(s)

	remote := "1.2.3.4:1"
	payload := []byte("HELLO")
	digest := md5.Sum(payload)

	_, err = c.Write([]byte{byte(packet), byte(len(remote))})
	require.NoError(t, err)
	_, err = c.Write([]byte(remote))
	require.NoError(t, err)
	_, err = c.Write(payload)
	require.NoError(t, err)
	_, err = c.Write(digest[:])
	require.NoError(t, err)
	require.NoError(t, c.Close())

	select {
	case p := <-tr.PacketCh():
		require.Equal(t, payload, p.Buf)
		require.Equal(t, remote, p.From.String())
	case <-time.After(2 * time.Second):
		t.Fatal("expected packet with valid digest to be delivered")
	}
}
