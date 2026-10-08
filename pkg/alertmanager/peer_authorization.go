// SPDX-License-Identifier: Apache-2.0

package alertmanager

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/go-kit/log/level"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// authorizePeer verifies that the caller of an inter-Alertmanager gRPC method
// is a legitimate replica for the given tenant.
//
// This closes the "Unauthenticated Alertmanager gRPC service trusts
// self-asserted X-Scope-OrgID" trust gap: UpdateState, ReadState and
// HandleRequest previously derived the tenant exclusively from the
// X-Scope-OrgID gRPC metadata without any caller authentication or
// authorization. authorizePeer now additionally requires that the caller's
// network address matches one of the Alertmanager replicas that the ring maps
// the tenant to for RingOp.
//
// The check is gated by cfg.PeerAuthorizationEnabled so that this remediation
// is backward-compatible with deployments and tests that do not have ring
// coordinates (or have no sharding at all). Operators are strongly encouraged
// to enable this flag together with -server.grpc-tls-client-auth=
// RequireAndVerifyClientCert so that the "peer address" compared against the
// ring is also cryptographically attested by a client certificate.
func (am *MultitenantAlertmanager) authorizePeer(ctx context.Context, userID string) error {
	if !am.cfg.PeerAuthorizationEnabled {
		return nil
	}

	// Peer authorization is only meaningful when sharding is enabled, because
	// otherwise the ring has no notion of which replicas should legitimately
	// be exchanging state for a tenant. Non-sharded deployments must rely on
	// network-level controls (the operational guidance in the mitigation).
	if !am.cfg.ShardingEnabled || am.ring == nil {
		return status.Error(codes.PermissionDenied, "peer authorization requires sharding to be enabled")
	}

	peerHost, err := peerHostFromContext(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	set, err := am.ring.Get(shardByUser(userID), RingOp, nil, nil, nil)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "unable to resolve ring membership for tenant: %v", err)
	}

	for _, inst := range set.Instances {
		ringHost, _, splitErr := net.SplitHostPort(inst.GetAddr())
		if splitErr != nil {
			ringHost = inst.GetAddr()
		}
		if ringHost == peerHost {
			return nil
		}
	}

	level.Warn(am.logger).Log(
		"msg", "rejecting inter-alertmanager gRPC call: peer is not a replica for this tenant",
		"user", userID,
		"peer", peerHost,
	)
	return status.Error(codes.PermissionDenied, "peer is not a replica for this tenant")
}

// peerHostFromContext returns the caller's network host as the server observes
// it. When mutual TLS is in use we prefer identity material carried in the
// verified client certificate (DNSNames / IPAddresses SANs) so that a caller
// that spoofs a source IP via NAT/proxying cannot bypass the ring membership
// check. When mTLS is not in use the TCP peer address is used; this still
// forces an attacker to additionally spoof an IP that is in the ring, raising
// the bar compared to the previous unauthenticated behaviour.
func peerHostFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "", fmt.Errorf("no peer information in context")
	}

	// Prefer a verified client certificate when mTLS is configured.
	if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
		if len(tlsInfo.State.VerifiedChains) > 0 && len(tlsInfo.State.VerifiedChains[0]) > 0 {
			leaf := tlsInfo.State.VerifiedChains[0][0]
			if host := preferredSANHost(leaf); host != "" {
				return host, nil
			}
		}
		if len(tlsInfo.State.PeerCertificates) > 0 {
			if host := preferredSANHost(tlsInfo.State.PeerCertificates[0]); host != "" {
				return host, nil
			}
		}
	}

	if p.Addr == nil {
		return "", fmt.Errorf("peer address is unknown")
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		// p.Addr may already be bare (e.g. a unix socket); fall back to the
		// raw string so we at least compare consistently.
		return p.Addr.String(), nil
	}
	return host, nil
}

// preferredSANHost returns the first usable Subject Alternative Name for host
// matching against the ring. DNS SANs are preferred; otherwise the first IP
// SAN is returned.
func preferredSANHost(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	return ""
}
