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

// reservedCIDRs contains additional IPv4/IPv6 ranges that must be treated as
// non-routable or otherwise unsafe destinations when the per-tenant receivers
// firewall is enabled. These complement the stdlib net.IP predicates
// (IsUnspecified / IsLoopback / IsLinkLocal* / IsInterfaceLocalMulticast /
// IsMulticast) and the existing RFC1918 / RFC4193 private checks.
//
// Covered ranges:
//   - 0.0.0.0/8           "This network" (RFC1122). 0.0.0.0 itself is caught
//                         by IsUnspecified; the rest of the /8 is reserved.
//   - 100.64.0.0/10       Carrier-grade NAT (RFC6598). Alibaba Cloud IMDS
//                         lives at 100.100.100.200 inside this range.
//   - 169.254.0.0/16      Link-local (IsLinkLocalUnicast already covers it
//                         but we keep it for defence-in-depth / clarity;
//                         AWS/GCP IMDS lives at 169.254.169.254).
//   - 192.0.0.0/24        IETF protocol assignments (RFC6890).
//   - 192.0.2.0/24        TEST-NET-1 (RFC5737).
//   - 198.18.0.0/15       Benchmarking (RFC2544).
//   - 198.51.100.0/24     TEST-NET-2 (RFC5737).
//   - 203.0.113.0/24      TEST-NET-3 (RFC5737).
//   - 240.0.0.0/4         Reserved for future use (RFC1112) incl.
//                         255.255.255.255 limited broadcast.
//   - ::/128              IPv6 unspecified (also caught by IsUnspecified).
//   - ::1/128             IPv6 loopback (also caught by IsLoopback).
//   - 64:ff9b::/96        NAT64 well-known prefix (RFC6052).
//   - 64:ff9b:1::/48      NAT64 local-use prefix (RFC8215).
//   - 100::/64            Discard-only (RFC6666).
//   - 2001::/32           Teredo (RFC4380).
//   - 2001:db8::/32       Documentation (RFC3849).
//   - fec0::/10           Deprecated site-local (RFC3879).
var reservedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"2001::/32",
		"2001:db8::/32",
		"fec0::/10",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// Programmer error: the list above is a compile-time constant.
			panic("firewall_dialer: invalid reserved CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

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

	if blockPrivateAddresses && (isPrivate(ip) || isLocal(ip) || isReserved(ip)) {
		return errBlockedAddress
	}

	for _, cidr := range blockCIDRNetworks {
		if cidr.Value.Contains(ip) {
			return errBlockedAddress
		}
	}

	return nil
}

// isLocal reports whether ip is a non-routable local address. It is
// deliberately conservative: in addition to loopback and link-local addresses
// it also rejects the unspecified address (0.0.0.0 / ::), which on Linux
// resolves to a loopback destination on connect(), and all multicast /
// broadcast destinations which must not be dialed as unicast TCP targets.
func isLocal(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		isBroadcast(ip)
}

// isBroadcast reports whether ip is the IPv4 limited broadcast address
// 255.255.255.255. Subnet-directed broadcast addresses are not detectable
// without local interface context and are covered by the RFC1918 checks for
// the common cases.
func isBroadcast(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 0xff && ip4[1] == 0xff && ip4[2] == 0xff && ip4[3] == 0xff
}

// isReserved reports whether ip falls inside any additional reserved /
// non-routable range that must not be reachable through the receivers
// firewall. See reservedCIDRs for the list and rationale.
func isReserved(ip net.IP) bool {
	for _, n := range reservedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivate reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
//
// This function has been copied from golang and should be removed once
// we'll upgrade to go 1.17. See: https://github.com/golang/go/pull/42793
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Following RFC 4193, Section 3. Local IPv6 Unicast Addresses which says:
		//   The Internet Assigned Numbers Authority (IANA) has reserved the
		//   following three blocks of the IPv4 address space for private internets:
		//     10.0.0.0        -   10.255.255.255  (10/8 prefix)
		//     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		//     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Following RFC 4193, Section 3. Private Address Space which says:
	//   The Internet Assigned Numbers Authority (IANA) has reserved the
	//   following block of the IPv6 address space for local internets:
	//     FC00::  -  FDFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF (FC00::/7 prefix)
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}
