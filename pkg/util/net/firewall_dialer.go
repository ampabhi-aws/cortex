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

// isLocal reports whether ip refers to the local host or an otherwise
// non-routable address that the kernel/link-layer may deliver locally.
// In particular IsUnspecified() must be included: on Linux/BSD a connect()
// to 0.0.0.0 or :: is delivered to loopback, so without this check a
// tenant-controlled receiver URL such as http://0.0.0.0:<port>/<path>
// bypasses the firewall and reaches loopback-only services.
func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || // 0.0.0.0 and :: route to localhost
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

// isPrivate reports whether ip is a non-routable (private, shared, benchmark,
// protocol-assignments, site-local or broadcast) address. This is a
// deliberately broader definition than Go's stdlib net.IP.IsPrivate (which
// only covers RFC 1918 / RFC 4193) because the firewall must fail closed on
// every address that is not a routable public destination; otherwise a
// tenant-controlled receiver URL can reach CGNAT pod CIDRs, TEST-NET ranges,
// benchmarking ranges, or site-local IPv6 addresses that are often reachable
// from within the pod/VM.
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 0 || // 0.0.0.0/8 "this network" (RFC 1122)
			ip4[0] == 10 || // 10.0.0.0/8 (RFC 1918)
			(ip4[0] == 100 && ip4[1]&0xc0 == 64) || // 100.64.0.0/10 CGNAT / EKS pod CIDRs (RFC 6598)
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) || // 172.16.0.0/12 (RFC 1918)
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0) || // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
			(ip4[0] == 192 && ip4[1] == 168) || // 192.168.0.0/16 (RFC 1918)
			(ip4[0] == 198 && ip4[1]&0xfe == 18) || // 198.18.0.0/15 benchmarking (RFC 2544)
			ip4.Equal(net.IPv4bcast) // 255.255.255.255 limited broadcast
	}
	// IPv6: fc00::/7 unique local (RFC 4193) and fec0::/10 site-local (RFC 3879, deprecated but still routable on some networks).
	return len(ip) == net.IPv6len && (ip[0]&0xfe == 0xfc || (ip[0] == 0xfe && ip[1]&0xc0 == 0xc0))
}
