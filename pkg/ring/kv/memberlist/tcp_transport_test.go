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

// TestTCPTransport_HandleConnection_PacketDigestMismatch verifies that a packet
// whose trailing md5 digest does not match the payload is dropped: nothing must
// be delivered on PacketCh(). This is a regression test for a missing `return`
// in the digest-mismatch branch of handleConnection, which previously caused
// corrupted/truncated frames to be forwarded to memberlist.
func TestTCPTransport_HandleConnection_PacketDigestMismatch(t *testing.T) {
	logs := &concurrency.SyncBuffer{}
	logger := log.NewLogfmtLogger(logs)

	cfg := TCPTransportConfig{}
	flagext.DefaultValues(&cfg)
	cfg.BindAddrs = []string{"localhost"}
	cfg.BindPort = 0

	transport, err := NewTCPTransport(cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transport.Shutdown() })

	addr := net.JoinHostPort("localhost", fmt.Sprintf("%d", transport.GetAutoBindPort()))

	// Frame format: [0x01][len(advertisedAddr)][advertisedAddr][payload][md5(payload)].
	// We deliberately send a WRONG trailing digest so that the integrity check fails.
	advertised := "127.0.0.1:12345"
	payload := []byte("this is some arbitrary payload bytes")
	badDigest := make([]byte, md5.Size) // all zeros, intentionally does NOT match md5(payload)

	frame := []byte{byte(packet)}
	frame = append(frame, byte(len(advertised)))
	frame = append(frame, []byte(advertised)...)
	frame = append(frame, payload...)
	frame = append(frame, badDigest...)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = conn.Write(frame)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// Nothing must be delivered on the packet channel within a reasonable timeout.
	select {
	case pkt := <-transport.PacketCh():
		t.Fatalf("expected no packet to be delivered on digest mismatch, got %q", string(pkt.Buf))
	case <-time.After(500 * time.Millisecond):
		// expected: packet dropped
	}

	assert.Contains(t, logs.String(), "packet digest mismatch")
}
