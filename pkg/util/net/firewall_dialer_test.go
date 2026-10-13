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
				{"0.0.0.0", true},                  // Unspecified IPv4 (connects to loopback on Linux)
				{"::", true},                       // Unspecified IPv6
				{"192.168.0.1", true},
				{"10.0.0.1", true},
				{"100.64.0.1", true},               // RFC 6598 CGNAT
				{"100.127.255.255", true},          // RFC 6598 CGNAT upper edge
				{"100.63.255.255", false},          // Just below RFC 6598
				{"100.128.0.0", false},             // Just above RFC 6598
				{"192.0.0.1", true},                // RFC 5736 (192.0.0.0/24)
				{"192.0.2.1", true},                // RFC 5737 TEST-NET-1
				{"198.51.100.1", true},             // RFC 5737 TEST-NET-2
				{"203.0.113.1", true},              // RFC 5737 TEST-NET-3
				{"198.18.0.1", true},               // RFC 2544 benchmarking
				{"198.19.255.255", true},           // RFC 2544 benchmarking upper
				{"239.0.0.1", true},                // IPv4 multicast
				{"255.255.255.255", true},          // IPv4 limited broadcast
				{"ff02::1", true},                  // IPv6 link-local multicast
				{"ff01::1", true},                  // IPv6 interface-local multicast
				{"ff0e::1", true},                  // IPv6 global multicast
				{"2002:7f00:1::", true},            // 6to4 embedding 127.0.0.1
				{"64:ff9b::7f00:1", true},          // NAT64 well-known prefix
				{"google.com", false},
				{"172.217.168.78", false},
				{"fdf8:f53b:82e4::53", true},       // Local
				{"fe80::200:5aee:feaa:20a2", true}, // Link-local
				{"2001:4860:4860::8844", false},    // Google DNS
				{"::ffff:172.217.168.78", false},   // IPv6 mapped v4 non-private
				{"::ffff:192.168.0.1", true},       // IPv6 mapped v4 private
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
		{net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{net.IP{0xfc, 0xff, 0x12, 0, 0, 0, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{net.IP{0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
		{net.IP{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true},
		{net.IP{0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
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
