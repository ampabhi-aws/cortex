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

// blockedNets is the deny-list of special-purpose IP prefixes that must never
// be reachable when BlockPrivateAddresses() is enabled. It covers the IPv4
// and IPv6 ranges that are either private, link-local, loopback,
// benchmarking, broadcast, multicast or otherwise non-routable on the public
// Internet. See IANA's "IANA IPv4 Special-Purpose Address Registry" and
// "IANA IPv6 Special-Purpose Address Registry".
//
// Note: the unspecified addresses (0.0.0.0/32 and ::/128), loopback,
// link-local and multicast ranges are also handled by the explicit
// net.IP method checks in isBlocked, so this list is defence-in-depth
// against partial-match edge cases (e.g. IPv4-mapped IPv6 forms).
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",          // RFC1122 "this network"
		"10.0.0.0/8",         // RFC1918
		"100.64.0.0/10",      // RFC6598 CGNAT
		"127.0.0.0/8",        // RFC1122 loopback
		"169.254.0.0/16",     // RFC3927 link-local
		"172.16.0.0/12",      // RFC1918
		"192.0.0.0/24",       // RFC6890 IETF protocol assignments
		"192.168.0.0/16",     // RFC1918
		"198.18.0.0/15",      // RFC2544 benchmarking
		"224.0.0.0/4",        // RFC5771 multicast
		"255.255.255.255/32", // RFC919 limited broadcast
		"::/128",             // RFC4291 unspecified
		"::1/128",            // RFC4291 loopback
		"fc00::/7",           // RFC4193 unique local
		"fe80::/10",          // RFC4291 link-local
		"ff00::/8",           // RFC4291 multicast
		"64:ff9b::/96",       // RFC6052 IPv4/IPv6 translation (NAT64)
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// This should never happen because the list is a compile-time
			// constant: fail loudly rather than silently permit traffic.
			panic("firewall_dialer: invalid CIDR in blockedNets: " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// isBlocked reports whether the given IP must be rejected when
// BlockPrivateAddresses() is true. It rejects the IPv4/IPv6 unspecified
// addresses, loopback, link-local (unicast and multicast), multicast and
// every prefix listed in blockedNets. Callers should pass the canonical
// form (use ip.To4() first when applicable) so that IPv4-mapped IPv6
// addresses are matched against the IPv4 prefixes.
func isBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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

	// Normalise IPv4-in-IPv6 to its 4-byte form so the IPv4 prefixes in
	// blockedNets match the IPv4-mapped IPv6 representation
	// (e.g. ::ffff:127.0.0.1).
	normalised := ip
	if v4 := ip.To4(); v4 != nil {
		normalised = v4
	}

	if blockPrivateAddresses && isBlocked(normalised) {
		return errBlockedAddress
	}

	for _, cidr := range blockCIDRNetworks {
		if cidr.Value.Contains(normalised) {
			return errBlockedAddress
		}
	}

	return nil
}
