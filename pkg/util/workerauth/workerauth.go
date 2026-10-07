// Package workerauth exposes helpers that identify the gRPC peer calling an
// intra-cluster worker control-plane RPC (for example the query-scheduler's
// NotifyQuerierShutdown or the v1 query-frontend's NotifyClientShutdown).
//
// Unlike middleware.ServerUserHeaderInterceptor these helpers derive the
// caller's identity from authenticated transport-level material whenever
// possible, falling back to the client-supplied X-Scope-OrgID metadata when
// mTLS has not been configured on the cluster gRPC port.  Callers can then
// bind sensitive request fields (e.g. QuerierID / ClientID) to the identified
// peer so an unauthenticated attacker that can reach the gRPC port cannot
// impersonate a different worker.
package workerauth

import (
	"context"

	"github.com/weaveworks/common/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ErrNoPeerIdentity is returned when the caller could not be identified from
// transport-level credentials or request metadata.
var ErrNoPeerIdentity = status.Error(codes.Unauthenticated, "worker peer identity is not available on this connection")

// AuthenticatedPeerID returns the identity of the gRPC caller.
//
// Preference order:
//
//  1. The Common Name of the verified TLS client certificate presented via
//     mTLS, when the server was configured with -server.grpc-tls-client-auth.
//     This is a cryptographically authenticated identity.
//  2. The X-Scope-OrgID header carried in the incoming request metadata.
//     This is not authenticated by itself but, when combined with network
//     isolation of the cluster gRPC port, lets a worker self-identify so the
//     handler can refuse requests that reference somebody else's ID.
//
// If neither source yields a non-empty identity, ErrNoPeerIdentity is
// returned with gRPC code Unauthenticated.
func AuthenticatedPeerID(ctx context.Context) (string, error) {
	if id, ok := tlsPeerCommonName(ctx); ok {
		return id, nil
	}
	if id, _, err := user.ExtractFromGRPCRequest(ctx); err == nil && id != "" {
		return id, nil
	}
	return "", ErrNoPeerIdentity
}

// tlsPeerCommonName returns the Common Name of the verified TLS client
// certificate on the current connection, if any.  Only the first verified
// chain's leaf certificate is consulted — matching the standard behaviour of
// Go's crypto/tls package when ClientAuth is RequireAndVerifyClientCert.
func tlsPeerCommonName(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	// VerifiedChains is non-empty only when the gRPC server verified the
	// client's certificate against the configured CA pool.
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", false
	}
	cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	if cn == "" {
		return "", false
	}
	return cn, true
}

