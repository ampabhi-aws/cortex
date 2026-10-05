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

// isLocal reports whether ip refers to the local host or a locally
// reachable scope that should never be the target of a server-side request
// originating from a tenant-controlled URL. This covers:
//   - the IPv4/IPv6 unspecified addresses (0.0.0.0, ::) which the kernel
//     routes to the local host on connect(),
//   - loopback (127.0.0.0/8, ::1),
//   - IPv4 limited broadcast (255.255.255.255),
//   - link-local unicast (169.254.0.0/16, fe80::/10),
//   - any multicast address (224.0.0.0/4, ff00::/8), which must never be
//     the destination of a unicast TCP dial but which, if ever permitted,
//     could reach link-local services.
func isLocal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// IPv4 limited broadcast.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0xff && ip4[1] == 0xff && ip4[2] == 0xff && ip4[3] == 0xff {
			return true
		}
	}
	return false
}

// isPrivate reports whether ip is a private, shared, benchmark, documentation,
// or otherwise non-globally-routable address that must not be reachable from
// a tenant-controlled URL. It covers:
//
// IPv4:
//   - RFC 1918 private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   - RFC 6598 shared / CGNAT: 100.64.0.0/10 (pod/node CIDRs on managed k8s,
//     some cloud metadata-like services)
//   - RFC 7600 "this network": 0.0.0.0/8 (also an unspecified-prefix bypass)
//   - RFC 6890 IETF protocol assignments: 192.0.0.0/24
//   - RFC 2544 benchmarking: 198.18.0.0/15
//   - RFC 5737 documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
//   - Reserved/future use: 240.0.0.0/4 (includes 255.255.255.255 which is
//     also handled by isLocal)
//
// IPv6:
//   - RFC 4193 unique local: fc00::/7
//   - RFC 3879 deprecated site-local: fec0::/10
//   - RFC 3056 6to4: 2002::/16 — the embedded IPv4 address decides routing,
//     so this can resolve to 169.254.169.254 in 6to4-enabled environments
//   - RFC 6052 NAT64 well-known prefix: 64:ff9b::/96 and 64:ff9b:1::/48
//   - IPv4-compatible IPv6 (::a.b.c.d) and IPv4-mapped IPv6 (::ffff:a.b.c.d):
//     the embedded IPv4 is checked recursively, so e.g. ::169.254.169.254 or
//     ::ffff:10.0.0.1 are classified by their IPv4 value.
func isPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// For IPv4 (and IPv4-mapped IPv6, which To4 normalises), classify by
	// the four-byte representation.
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 0: // 0.0.0.0/8 "this network"
			return true
		case ip4[0] == 10: // 10.0.0.0/8
			return true
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT / shared
			return true
		case ip4[0] == 172 && ip4[1]&0xf0 == 16: // 172.16.0.0/12
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24 IETF
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2: // 192.0.2.0/24 TEST-NET-1
			return true
		case ip4[0] == 192 && ip4[1] == 168: // 192.168.0.0/16
			return true
		case ip4[0] == 198 && ip4[1]&0xfe == 18: // 198.18.0.0/15 benchmarking
			return true
		case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100: // 198.51.100.0/24 TEST-NET-2
			return true
		case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113: // 203.0.113.0/24 TEST-NET-3
			return true
		case ip4[0]&0xf0 == 0xf0: // 240.0.0.0/4 reserved (includes 255.255.255.255)
			return true
		}
		return false
	}

	if len(ip) != net.IPv6len {
		return false
	}

	// RFC 4193 fc00::/7 unique local.
	if ip[0]&0xfe == 0xfc {
		return true
	}
	// RFC 3879 fec0::/10 deprecated site-local.
	if ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 {
		return true
	}
	// RFC 3056 2002::/16 6to4 — classify by the embedded IPv4 (bytes 2..5).
	if ip[0] == 0x20 && ip[1] == 0x02 {
		embedded := net.IPv4(ip[2], ip[3], ip[4], ip[5])
		if isPrivate(embedded) || isLocal(embedded) {
			return true
		}
		// Any 6to4 address is also effectively treated as suspect since it
		// transits through a 6to4 relay to an IPv4 destination.
		return true
	}
	// RFC 6052 NAT64 well-known prefix 64:ff9b::/96 — bytes 0..11 are
	// 00 64 ff 9b 00 00 00 00 00 00 00 00, embedded IPv4 at bytes 12..15.
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		embedded := net.IPv4(ip[12], ip[13], ip[14], ip[15])
		if isPrivate(embedded) || isLocal(embedded) {
			return true
		}
		return true
	}
	// IPv4-compatible IPv6 (::a.b.c.d, deprecated by RFC 4291) — bytes 0..11
	// are zero and the embedded IPv4 is at bytes 12..15. Exclude ::1 (loopback)
	// and :: (unspecified) which are handled by isLocal.
	if isZeroPrefix12(ip) && !(ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && (ip[15] == 0 || ip[15] == 1)) {
		embedded := net.IPv4(ip[12], ip[13], ip[14], ip[15])
		if isPrivate(embedded) || isLocal(embedded) {
			return true
		}
		// Otherwise this is an IPv4-compatible IPv6 pointing at a public IPv4;
		// treat it as suspect because this transition format is deprecated and
		// typically relays through local kernel paths.
		return true
	}
	return false
}

// isZeroPrefix12 reports whether the first 12 bytes of a 16-byte IPv6 are all
// zero (i.e. the address is of the form ::a.b.c.d).
func isZeroPrefix12(ip net.IP) bool {
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}
