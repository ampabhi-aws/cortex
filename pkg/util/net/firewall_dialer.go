package net

import (
	"context"
	"net"
	"net/url"
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

func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// IsBlockedAddress reports whether the given IP would be refused by a
// FirewallDialer configured with the supplied options. It is exported so
// admission-time validators (for example, Cortex's Alertmanager config API)
// can reject tenant-supplied URLs that resolve to firewalled addresses rather
// than relying solely on a dial-time hook, which can be bypassed by code paths
// (for example OAuth2 token clients) that construct independent transports
// without the hook.
func IsBlockedAddress(ip net.IP, blockPrivateAddresses bool, blockCIDRNetworks []flagext.CIDR) bool {
	if !blockPrivateAddresses && len(blockCIDRNetworks) == 0 {
		return false
	}
	if blockPrivateAddresses && (isPrivate(ip) || isLocal(ip)) {
		return true
	}
	for _, cidr := range blockCIDRNetworks {
		if cidr.Value.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateURLAgainstFirewall parses rawURL and returns an error if the URL's
// host resolves (via net.DefaultResolver) to any address that would be refused
// by a FirewallDialer configured with blockPrivateAddresses and
// blockCIDRNetworks. An empty rawURL is considered valid (nothing to check).
//
// Enforcement is best-effort: it hardens admission control but cannot by
// itself defeat DNS rebinding — the dial-time hook must also be applied by
// every HTTP transport that eventually sends tenant traffic.
func ValidateURLAgainstFirewall(rawURL string, blockPrivateAddresses bool, blockCIDRNetworks []flagext.CIDR) error {
	if rawURL == "" {
		return nil
	}
	if !blockPrivateAddresses && len(blockCIDRNetworks) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.Wrapf(errInvalidAddress, "could not parse URL %q", rawURL)
	}
	host := u.Hostname()
	if host == "" {
		return errors.Wrapf(errInvalidAddress, "URL %q has no host", rawURL)
	}
	// Literal IP: check directly.
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedAddress(ip, blockPrivateAddresses, blockCIDRNetworks) {
			return errors.Wrapf(errBlockedAddress, "URL %q resolves to a blocked address", rawURL)
		}
		return nil
	}
	// Hostname: resolve and check every answer. Fail closed if any resolved
	// address is blocked, but do not fail if resolution itself fails — the
	// dial-time check will still refuse the connection.
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil
	}
	for _, ipAddr := range ips {
		if IsBlockedAddress(ipAddr.IP, blockPrivateAddresses, blockCIDRNetworks) {
			return errors.Wrapf(errBlockedAddress, "URL %q resolves to a blocked address", rawURL)
		}
	}
	return nil
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
