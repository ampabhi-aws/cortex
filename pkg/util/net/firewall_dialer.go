package net

import (
	"context"
	"net"
	"syscall"

	"github.com/pkg/errors"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

var errBlockedAddress = errors.New("blocked address")
var errInvalidAddress = errors.New("invalid address")

type FirewallDialerConfigProvider interface {
	BlockCIDRNetworks() []flagext.CIDR
	BlockPrivateAddresses() bool
}

// FirewallDialer is a net dialer which integrates a firewall to block specific addresses.
type FirewallDialer struct {
	parent      *net.Dialer
	cfgProvider FirewallDialerConfigProvider
}

func NewFirewallDialer(cfgProvider FirewallDialerConfigProvider) *FirewallDialer {
	d := &FirewallDialer{cfgProvider: cfgProvider}
	d.parent = &net.Dialer{Control: d.control}
	return d
}

func (d *FirewallDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.parent.DialContext(ctx, network, address)
}

func (d *FirewallDialer) control(_, address string, _ syscall.RawConn) error {
	blockPrivateAddresses := d.cfgProvider.BlockPrivateAddresses()
	blockCIDRNetworks := d.cfgProvider.BlockCIDRNetworks()

	// Skip any control if no firewall has been configured.
	if !blockPrivateAddresses && len(blockCIDRNetworks) == 0 {
		return nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errInvalidAddress
	}

	// We expect an IP as address because the DNS resolution already occurred.
	ip := net.ParseIP(host)
	if ip == nil {
		return errBlockedAddress
	}

	if blockPrivateAddresses && (isPrivate(ip) || isLocal(ip)) {
		return errBlockedAddress
	}

	for _, cidr := range blockCIDRNetworks {
		if cidr.Value.Contains(ip) {
			return errBlockedAddress
		}
	}

	return nil
}

// isLocal reports whether ip is a local address that must not be reachable
// via tenant-controlled receiver endpoints. This covers:
//   - the unspecified address (0.0.0.0, ::) which on Linux resolves to loopback
//     when used as a connect destination;
//   - loopback (127.0.0.0/8, ::1);
//   - link-local unicast and multicast (169.254.0.0/16, fe80::/10, 224.0.0.0/24, ff02::/16);
//   - interface-local multicast (ff01::/16);
//   - any IPv4/IPv6 multicast (224.0.0.0/4, ff00::/8);
//   - the IPv4 limited broadcast address 255.255.255.255.
func isLocal(ip net.IP) bool {
	if ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}
	// Limited broadcast (255.255.255.255).
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0xff && ip4[1] == 0xff && ip4[2] == 0xff && ip4[3] == 0xff {
			return true
		}
	}
	return false
}

// isPrivate reports whether ip is a private, shared, or otherwise non-globally
// routable address that must not be reachable via tenant-controlled receiver
// endpoints when the firewall is enabled. This covers:
//   - RFC 1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16);
//   - RFC 6598 shared address space / CGNAT (100.64.0.0/10);
//   - RFC 5736 IETF protocol assignments (192.0.0.0/24);
//   - RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24);
//   - RFC 2544 benchmarking (198.18.0.0/15);
//   - RFC 4193 unique local IPv6 addresses (fc00::/7);
//   - 6to4 (2002::/16) and NAT64 well-known prefix (64:ff9b::/96) which can
//     map back to internal IPv4 destinations.
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		// RFC 1918 (10/8, 172.16/12, 192.168/16).
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1]&0xf0 == 16:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		// RFC 6598 shared address space (100.64.0.0/10).
		case ip4[0] == 100 && ip4[1]&0xc0 == 64:
			return true
		// RFC 5736 IETF protocol assignments (192.0.0.0/24).
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0:
			return true
		// RFC 5737 documentation ranges.
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2:
			return true
		case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100:
			return true
		case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113:
			return true
		// RFC 2544 benchmarking (198.18.0.0/15).
		case ip4[0] == 198 && ip4[1]&0xfe == 18:
			return true
		}
		return false
	}
	if len(ip) != net.IPv6len {
		return false
	}
	// RFC 4193 unique local IPv6 (fc00::/7).
	if ip[0]&0xfe == 0xfc {
		return true
	}
	// 6to4 (2002::/16) — may embed internal IPv4 destinations.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return true
	}
	// NAT64 well-known prefix (64:ff9b::/96).
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		return true
	}
	return false
}
