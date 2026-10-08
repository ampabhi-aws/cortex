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

	// Normalise IPv4-mapped IPv6 addresses to their IPv4 form so that
	// block_cidr_networks entries written as IPv4 CIDRs match the mapped form,
	// and so the per-family classification below sees the canonical address.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if blockPrivateAddresses && isBlocked(ip) {
		return errBlockedAddress
	}

	for _, cidr := range blockCIDRNetworks {
		if cidr.Value.Contains(ip) {
			return errBlockedAddress
		}
	}

	return nil
}

// blockedNets is the explicit reserved-range denylist applied when
// BlockPrivateAddresses is enabled. The list fails closed: it includes every
// non-globally-routable IPv4 and IPv6 range (RFC 1918, RFC 6598 CGNAT,
// loopback, link-local incl. cloud metadata, IETF protocol assignments,
// documentation, benchmarking, 6to4 anycast, broadcast/multicast, and the
// corresponding IPv6 blocks). The unspecified address (0.0.0.0, ::) is
// included via 0.0.0.0/8 and ::/128, closing the loophole where connect(2)
// to the unspecified address is resolved by the kernel to the local host.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",      // "this network" incl. the unspecified address
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local incl. cloud metadata (169.254.169.254)
		"100.64.0.0/10",  // RFC 6598 CGNAT / managed-k8s pod-service ranges
		"192.0.0.0/24",   // IETF protocol assignments (incl. 192.0.0.192 NAT64)
		"192.0.2.0/24",   // TEST-NET-1 (documentation)
		"192.88.99.0/24", // 6to4 relay anycast (deprecated)
		"198.18.0.0/15",  // benchmarking (used by some service meshes)
		"198.51.100.0/24", // TEST-NET-2 (documentation)
		"203.0.113.0/24",  // TEST-NET-3 (documentation)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved (future use)
		"255.255.255.255/32", // limited broadcast
		"::/128",         // unspecified
		"::1/128",        // loopback
		"fc00::/7",       // unique local addresses (RFC 4193)
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast (incl. interface-local ff01::/16)
		"64:ff9b::/96",   // IPv4/IPv6 translation (RFC 6052)
		"2002::/16",      // 6to4
		"2001:db8::/32",  // documentation
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isBlocked reports whether ip is a non-globally-routable destination that
// must be denied when BlockPrivateAddresses is enabled. It fails closed:
// in addition to the explicit reserved-range CIDRs, it rejects any address
// Go's stdlib classifies as unspecified, loopback, link-local, multicast,
// interface-local multicast, or not globally unicast.
func isBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || !ip.IsGlobalUnicast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivate reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
//
// Retained for backwards compatibility with existing tests; the live
// classification used by control() is isBlocked, which is strictly
// broader (fails closed on the unspecified address and other reserved
// ranges that the hand-rolled helper did not cover).
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}
