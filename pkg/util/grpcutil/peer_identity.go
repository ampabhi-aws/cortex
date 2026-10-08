package grpcutil

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// AuthenticatedPeerIdentity extracts a verified transport-level peer identity
// (TLS client certificate Common Name) from the incoming gRPC context. It
// returns a non-empty identity ONLY if the peer presented a client certificate
// that was successfully verified by the TLS stack (i.e. the server was
// configured with -server.grpc-tls-client-auth=RequireAndVerifyClientCert or
// equivalent and the cert chained to a trusted CA).
//
// When no verified TLS peer identity is available (for example because mTLS
// is not configured on the gRPC listener, which is the historical default)
// the function returns an empty string with ok=false. Callers must therefore
// treat an empty return as "no authenticated peer identity available" rather
// than as an error, so this helper is safe to add to code paths that must
// continue to work in non-mTLS deployments.
func AuthenticatedPeerIdentity(ctx context.Context) (identity string, ok bool) {
	p, exists := peer.FromContext(ctx)
	if !exists || p == nil || p.AuthInfo == nil {
		return "", false
	}
	tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
	if !isTLS {
		return "", false
	}
	// Require a verified chain. tls.ConnectionState.VerifiedChains is only
	// populated when ClientAuth is RequireAndVerifyClientCert (or the
	// equivalent VerifyClientCertIfGiven path has produced a verified
	// chain). PeerCertificates alone is insufficient because an attacker
	// could present an untrusted cert when ClientAuth is less strict.
	state := tlsInfo.State
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", false
	}
	cert := state.VerifiedChains[0][0]
	if cert == nil {
		return "", false
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		return "", false
	}
	return cn, true
}
