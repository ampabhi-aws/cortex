// Package operator provides a small helper to mark an in-process gRPC call
// as originating from a trusted Cortex component (e.g. the distributor
// aggregating per-tenant metrics across ingesters) rather than from a
// tenant-scoped caller.
//
// Cortex-internal cluster-wide RPCs such as Ingester.AllUserStats must not
// honour an arbitrary caller-supplied X-Scope-OrgID header: the only reason
// such a header was ever attached was so the shared gRPC auth middleware
// (ServerUserHeaderInterceptor) did not reject the call. The handlers now
// additionally require this operator marker so that a request from an
// untrusted tenant on the same gRPC listener (which can supply any value
// for X-Scope-OrgID) cannot enumerate every tenant on the ingester.
//
// The marker is intentionally transport-local: it is appended as outgoing
// gRPC metadata by the trusted caller (which runs in the same process as
// the server when Cortex is deployed in single-binary mode, or runs behind
// the same cluster-internal network boundary otherwise) and verified from
// the incoming metadata by the server. It is not forwarded over HTTP or
// propagated across tenant-facing surfaces.
package operator

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// InternalMetadataKey is the gRPC metadata key used to carry the internal
// operator marker between trusted Cortex components. gRPC metadata keys are
// case-insensitive and canonicalised to lower case by the runtime.
const InternalMetadataKey = "x-cortex-internal-operator"

// internalMarkerValue is the opaque sentinel value appended under
// InternalMetadataKey. The value itself is not a secret: this marker only
// distinguishes an in-process call from the distributor from an external
// tenant request that just supplies an X-Scope-OrgID header. Deployments
// that need protection from arbitrary callers on the ingester gRPC port
// must still terminate client authentication at the cluster boundary
// (mTLS / network policy / front proxy), as documented in
// docs/guides/authentication-and-authorisation.md.
const internalMarkerValue = "cortex"

// AppendOutgoing returns a context that will carry the internal operator
// marker on any gRPC call made with it. Trusted callers (e.g. the
// distributor) use this when invoking cluster-wide RPCs that must not be
// callable by tenant-scoped peers.
func AppendOutgoing(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, InternalMetadataKey, internalMarkerValue)
}

// WithIncomingForTest returns a context whose incoming gRPC metadata
// carries the internal operator marker. It is intended for unit tests that
// invoke server handlers directly (bypassing the gRPC stack), and must not
// be used on production call paths.
func WithIncomingForTest(ctx context.Context) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs(InternalMetadataKey, internalMarkerValue))
}

// IsInternalCaller reports whether the incoming gRPC metadata on ctx
// carries the internal operator marker. It is safe to call on contexts
// that do not originate from a gRPC server (it simply returns false).
func IsInternalCaller(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, v := range md.Get(InternalMetadataKey) {
		if v == internalMarkerValue {
			return true
		}
	}
	return false
}
