package net

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func TestFirewallDialer(t *testing.T) {
	blockedCIDR := flagext.CIDR{}
	require.NoError(t, blockedCIDR.Set("172.217.168.64/28"))

	type testCase struct {
		address       string
		expectBlocked bool
	}

	tests := map[string]struct {
		cfg   FirewallDialerConfigProvider
		cases []testCase
	}{
		"should not block traffic with no block config": {
			cfg: firewallCfgProvider{},
			cases: []testCase{
				{"localhost", false},
				{"127.0.0.1", false},
				{"google.com", false},
				{"172.217.168.78", false},
			},
		},
		"should support blocking private addresses": {
			cfg: firewallCfgProvider{
				blockPrivateAddresses: true,
			},
			cases: []testCase{
				{"localhost", true},
				{"127.0.0.1", true},
				{"192.168.0.1", true},
				{"10.0.0.1", true},
				{"google.com", false},
				{"172.217.168.78", false},
				{"fdf8:f53b:82e4::53", true},       // Local
				{"fe80::200:5aee:feaa:20a2", true}, // Link-local
				{"2001:4860:4860::8844", false},    // Google DNS
				{"::ffff:172.217.168.78", false},   // IPv6 mapped v4 non-private
				{"::ffff:192.168.0.1", true},       // IPv6 mapped v4 private
				// Previously-bypassable addresses (CWE-184 incomplete denylist).
				{"0.0.0.0", true},                 // IPv4 unspecified -> localhost on connect
				{"::", true},                      // IPv6 unspecified -> localhost on connect
				{"100.64.0.1", true},              // RFC 6598 CGNAT / shared
				{"100.127.255.254", true},         // RFC 6598 CGNAT upper edge
				{"100.128.0.1", false},            // just outside CGNAT /10
				{"192.0.0.192", true},             // RFC 6890 IETF protocol assignments
				{"192.0.2.1", true},               // RFC 5737 TEST-NET-1
				{"198.18.0.1", true},              // RFC 2544 benchmarking
				{"198.19.255.254", true},          // RFC 2544 benchmarking upper edge
				{"198.51.100.1", true},            // RFC 5737 TEST-NET-2
				{"203.0.113.1", true},             // RFC 5737 TEST-NET-3
				{"255.255.255.255", true},         // IPv4 limited broadcast
				{"240.0.0.1", true},               // reserved / future use
				{"224.0.0.1", true},               // link-local multicast
				{"239.255.255.250", true},         // admin-scoped multicast (SSDP)
				{"fec0::1", true},                 // deprecated IPv6 site-local
				{"ff02::1", true},                 // IPv6 link-local multicast
				{"ff05::1", true},                 // IPv6 site-local multicast
				{"::169.254.169.254", true},       // IPv4-compatible IPv6 pointing at link-local
				{"::ffff:169.254.169.254", true},  // IPv4-mapped IPv6 pointing at link-local
				{"2002:a9fe:a9fe::", true},        // 6to4 encapsulating 169.254.169.254
				{"64:ff9b::a9fe:a9fe", true},      // NAT64 well-known prefix -> 169.254.169.254
			},
		},
		"should support blocking custom CIDRs": {
			cfg: firewallCfgProvider{
				blockCIDRNetworks: []flagext.CIDR{blockedCIDR},
			},
			cases: []testCase{
				{"localhost", false},
				{"127.0.0.1", false},
				{"192.168.0.1", false},
				{"10.0.0.1", false},
				{"172.217.168.78", true},
				{"fdf8:f53b:82e4::53", false},       // Local
				{"fe80::200:5aee:feaa:20a2", false}, // Link-local
				{"2001:4860:4860::8844", false},     // Google DNS
				{"::ffff:10.0.0.1", false},          // IPv6 mapped v4 non-blocked
				{"::ffff:172.217.168.78", true},     // IPv6 mapped v4 blocked
			},
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			d := NewFirewallDialer(testData.cfg)

			for _, tc := range testData.cases {
				t.Run(fmt.Sprintf("address: %s", tc.address), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()

					conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("[%s]:80", tc.address))
					if conn != nil {
						require.NoError(t, conn.Close())
					}

					if tc.expectBlocked {
						assert.Error(t, err, errBlockedAddress.Error())
						assert.Contains(t, err.Error(), errBlockedAddress.Error())
					} else {
						// We're fine either if succeeded or triggered a different error (eg. connection refused).
						assert.True(t, err == nil || !strings.Contains(err.Error(), errBlockedAddress.Error()))
					}
				})
			}
		})
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip       net.IP
		expected bool
	}{
		{nil, false},
		{net.IPv4(1, 1, 1, 1), false},
		{net.IPv4(9, 255, 255, 255), false},
		{net.IPv4(10, 0, 0, 0), true},
		{net.IPv4(10, 255, 255, 255), true},
		{net.IPv4(11, 0, 0, 0), false},
		{net.IPv4(172, 15, 255, 255), false},
		{net.IPv4(172, 16, 0, 0), true},
		{net.IPv4(172, 16, 255, 255), true},
		{net.IPv4(172, 23, 18, 255), true},
		{net.IPv4(172, 31, 255, 255), true},
		{net.IPv4(172, 31, 0, 0), true},
		{net.IPv4(172, 32, 0, 0), false},
		{net.IPv4(192, 167, 255, 255), false},
		{net.IPv4(192, 168, 0, 0), true},
		{net.IPv4(192, 168, 255, 255), true},
		{net.IPv4(192, 169, 0, 0), false},
		// 0.0.0.0/8 "this network".
		{net.IPv4(0, 0, 0, 0), true},
		{net.IPv4(0, 1, 2, 3), true},
		// 100.64.0.0/10 CGNAT.
		{net.IPv4(100, 63, 255, 255), false},
		{net.IPv4(100, 64, 0, 0), true},
		{net.IPv4(100, 127, 255, 255), true},
		{net.IPv4(100, 128, 0, 0), false},
		// 192.0.0.0/24 IETF assignments.
		{net.IPv4(192, 0, 0, 0), true},
		{net.IPv4(192, 0, 0, 255), true},
		{net.IPv4(192, 0, 1, 0), false},
		// 192.0.2.0/24 TEST-NET-1.
		{net.IPv4(192, 0, 2, 1), true},
		// 198.18.0.0/15 benchmarking.
		{net.IPv4(198, 17, 255, 255), false},
		{net.IPv4(198, 18, 0, 0), true},
		{net.IPv4(198, 19, 255, 255), true},
		{net.IPv4(198, 20, 0, 0), false},
		// 198.51.100.0/24 TEST-NET-2.
		{net.IPv4(198, 51, 100, 1), true},
		// 203.0.113.0/24 TEST-NET-3.
		{net.IPv4(203, 0, 113, 1), true},
		// 240.0.0.0/4 reserved / future use.
		{net.IPv4(239, 255, 255, 255), false},
		{net.IPv4(240, 0, 0, 0), true},
		{net.IPv4(255, 255, 255, 255), true},
		// IPv6 RFC 4193 unique local.
		{net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{net.IP{0xfc, 0xff, 0x12, 0, 0, 0, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{net.IP{0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
		{net.IP{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true},
		{net.IP{0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
		// IPv6 fec0::/10 deprecated site-local.
		{net.ParseIP("fec0::1"), true},
		{net.ParseIP("feff::1"), true},
		// 6to4 encapsulating link-local metadata IP.
		{net.ParseIP("2002:a9fe:a9fe::"), true},
		// NAT64 well-known prefix pointing at link-local.
		{net.ParseIP("64:ff9b::a9fe:a9fe"), true},
		// IPv4-compatible IPv6 pointing at link-local.
		{net.ParseIP("::169.254.169.254"), true},
		// Unspecified / loopback are classified by isLocal, not isPrivate.
		{net.ParseIP("::"), false},
		{net.ParseIP("::1"), false},
	}

	for _, test := range tests {
		assert.Equalf(t, test.expected, isPrivate(test.ip), "ip: %s", test.ip.String())
	}
}

type firewallCfgProvider struct {
	blockCIDRNetworks     []flagext.CIDR
	blockPrivateAddresses bool
}

func (p firewallCfgProvider) BlockCIDRNetworks() []flagext.CIDR {
	return p.blockCIDRNetworks
}

func (p firewallCfgProvider) BlockPrivateAddresses() bool {
	return p.blockPrivateAddresses
}
