package memberlist

import (
	"crypto/md5"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/concurrency"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func TestTCPTransport_WriteTo_ShouldNotLogAsWarningExpectedFailures(t *testing.T) {
	tests := map[string]struct {
		setup          func(t *testing.T, cfg *TCPTransportConfig)
		remoteAddr     string
		expectedLogs   string
		unexpectedLogs string
	}{
		"should not log 'connection refused' by default": {
			remoteAddr:     "localhost:12345",
			unexpectedLogs: "connection refused",
		},
		"should log 'connection refused' if debug log level is enabled": {
			setup: func(t *testing.T, cfg *TCPTransportConfig) {
				cfg.TransportDebug = true
			},
			remoteAddr:   "localhost:12345",
			expectedLogs: "connection refused",
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			logs := &concurrency.SyncBuffer{}
			logger := log.NewLogfmtLogger(logs)

			cfg := TCPTransportConfig{}
			flagext.DefaultValues(&cfg)
			cfg.BindAddrs = []string{"localhost"}
			cfg.BindPort = 0
			if testData.setup != nil {
				testData.setup(t, &cfg)
			}

			transport, err := NewTCPTransport(cfg, logger)
			require.NoError(t, err)

			_, err = transport.WriteTo([]byte("test"), testData.remoteAddr)
			require.NoError(t, err)

			if testData.expectedLogs != "" {
				assert.Contains(t, logs.String(), testData.expectedLogs)
			}
			if testData.unexpectedLogs != "" {
				assert.NotContains(t, logs.String(), testData.unexpectedLogs)
			}
		})
	}
}

// TestTCPTransport_PacketWithBadDigestIsDropped verifies that a packet whose trailing
// MD5 digest does not match the computed digest of its payload is dropped by the
// transport (fail-closed) and never delivered on PacketCh.
func TestTCPTransport_PacketWithBadDigestIsDropped(t *testing.T) {
	logger := log.NewNopLogger()

	cfg := TCPTransportConfig{}
	flagext.DefaultValues(&cfg)
	cfg.BindAddrs = []string{"localhost"}
	cfg.BindPort = 0

	transport, err := NewTCPTransport(cfg, logger)
	require.NoError(t, err)
	defer func() { _ = transport.Shutdown() }()

	port := transport.GetAutoBindPort()
	require.NotZero(t, port)

	sendPacket := func(payload []byte, digest []byte) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		require.NoError(t, err)
		defer c.Close()

		// 1-byte message type (packet), 1-byte address length (0), payload, 16-byte digest.
		_, err = c.Write([]byte{byte(packet), 0x00})
		require.NoError(t, err)
		_, err = c.Write(payload)
		require.NoError(t, err)
		_, err = c.Write(digest)
		require.NoError(t, err)
	}

	payload := []byte("NOT-A-REAL-GOSSIP-PACKET")
	badDigest := make([]byte, md5.Size) // all zeros, guaranteed mismatch

	sendPacket(payload, badDigest)

	// The packet must NOT be forwarded to memberlist on PacketCh.
	select {
	case p := <-transport.PacketCh():
		t.Fatalf("packet with bad digest was delivered to packetCh: %q", p.Buf)
	case <-time.After(500 * time.Millisecond):
		// Expected: no packet delivered.
	}

	// And a packet with a correct digest should still be delivered, to make sure
	// we didn't just break the happy path.
	goodPayload := []byte("hello-cortex")
	goodDigest := md5.Sum(goodPayload)
	sendPacket(goodPayload, goodDigest[:])

	select {
	case p := <-transport.PacketCh():
		assert.Equal(t, goodPayload, p.Buf)
	case <-time.After(2 * time.Second):
		t.Fatal("packet with good digest was not delivered to packetCh")
	}
}
