package worker

import (
	"net"
	"strings"

	"github.com/pkg/errors"
)

// frontendAddressAllowlist implements an optional defense-in-depth check on
// the frontend address the querier is asked to dial when returning query
// results. The address is supplied by the (unauthenticated) query-scheduler
// FrontendLoop stream and therefore could be attacker-controlled on untrusted
// networks. When the allowlist is empty, every address is accepted so that
// deployments which have historically relied on the scheduler's assertion
// continue to work.
type frontendAddressAllowlist struct {
	// exact host:port entries
	hostPorts map[string]struct{}
	// exact host (no port) entries
	hosts map[string]struct{}
	// CIDR entries
	nets []*net.IPNet
}

func newFrontendAddressAllowlist(entries []string) *frontendAddressAllowlist {
	a := &frontendAddressAllowlist{
		hostPorts: map[string]struct{}{},
		hosts:     map[string]struct{}{},
	}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil && ipnet != nil {
			a.nets = append(a.nets, ipnet)
			continue
		}
		if host, _, err := net.SplitHostPort(entry); err == nil {
			a.hostPorts[strings.ToLower(entry)] = struct{}{}
			if host != "" {
				a.hosts[strings.ToLower(host)] = struct{}{}
			}
			continue
		}
		a.hosts[strings.ToLower(entry)] = struct{}{}
	}
	return a
}

// isEmpty reports whether no entries were configured. In that case check()
// permits every address (historical behavior).
func (a *frontendAddressAllowlist) isEmpty() bool {
	if a == nil {
		return true
	}
	return len(a.hostPorts) == 0 && len(a.hosts) == 0 && len(a.nets) == 0
}

// check returns nil when the given frontend address is permitted, or an error
// describing why it was rejected.
func (a *frontendAddressAllowlist) check(address string) error {
	if a.isEmpty() {
		return nil
	}
	if strings.TrimSpace(address) == "" {
		return errors.New("empty frontend address")
	}
	addrLower := strings.ToLower(address)
	if _, ok := a.hostPorts[addrLower]; ok {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	hostLower := strings.ToLower(host)
	if _, ok := a.hosts[hostLower]; ok {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range a.nets {
			if n.Contains(ip) {
				return nil
			}
		}
	}
	// For hostnames, allow them if any resolved IP falls inside a CIDR entry.
	if len(a.nets) > 0 && net.ParseIP(host) == nil {
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				for _, n := range a.nets {
					if n.Contains(ip) {
						return nil
					}
				}
			}
		}
	}
	return errors.Errorf("frontend address %q is not in the configured allowlist", address)
}
