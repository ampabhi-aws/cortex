// Package schedulerauth provides a minimal shared-secret authentication layer
// for Cortex' internal query-scheduler / query-frontend gRPC control plane.
//
// The query-scheduler and query-frontend expose a handful of streaming gRPC
// methods (SchedulerForFrontend/FrontendLoop, SchedulerForQuerier/QuerierLoop,
// SchedulerForQuerier/NotifyQuerierShutdown, Frontend/Process,
// Frontend/NotifyClientShutdown) that are intentionally exempted from the
// tenant-header auth interceptor because a single call multiplexes requests
// for many tenants. Historically these ports have therefore been completely
// unauthenticated and relied solely on network isolation. Operators that
// cannot fully rely on network isolation can set a shared secret via
// -api.internal-grpc-auth-token (identical value on every scheduler, every
// query-frontend and every querier). When set:
//
//   - Clients attach the secret as the "x-cortex-scheduler-auth" gRPC
//     metadata header on all outgoing calls to these methods, using the
//     unary and stream client interceptors returned here.
//   - Servers reject calls to those methods that do not present the correct
//     secret with codes.Unauthenticated, using the matching unary and stream
//     server interceptors returned here.
//
// When the shared secret is empty the behaviour is unchanged (defence in
// depth is opt-in and must not break existing deployments that rely on
// network isolation or on mTLS via server.grpc-tls-* / client-side
// grpc_client_config.tls_*).
package schedulerauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthTokenMetadataKey is the gRPC metadata header name used to carry the
// shared secret that authenticates callers of the internal scheduler /
// frontend control plane. The header name is lower-case per gRPC convention.
const AuthTokenMetadataKey = "x-cortex-scheduler-auth"

// GuardedServerMethods is the exhaustive list of gRPC fully-qualified method
// names that are exempted from the tenant-header auth interceptor and that
// therefore need a dedicated shared-secret check when one is configured.
//
// Keep this list in sync with the ignoredMethods passed to
// fakeauth.SetupAuthMiddleware in pkg/cortex/cortex.go.
var GuardedServerMethods = []string{
	"/frontend.Frontend/Process",
	"/frontend.Frontend/NotifyClientShutdown",
	"/schedulerpb.SchedulerForFrontend/FrontendLoop",
	"/schedulerpb.SchedulerForQuerier/QuerierLoop",
	"/schedulerpb.SchedulerForQuerier/NotifyQuerierShutdown",
}

// UnaryClientInterceptor returns a grpc.UnaryClientInterceptor that attaches
// the shared secret as metadata on every outgoing unary RPC. It is safe to
// install unconditionally: when token is empty the interceptor is a no-op.
func UnaryClientInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, AuthTokenMetadataKey, token)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a grpc.StreamClientInterceptor that
// attaches the shared secret as metadata on every outgoing streaming RPC.
// It is safe to install unconditionally: when token is empty the interceptor
// is a no-op.
func StreamClientInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, AuthTokenMetadataKey, token)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that rejects
// calls to the listed methods when the required shared secret is missing or
// does not match. When token is empty the interceptor is a no-op (defence in
// depth is opt-in).
func UnaryServerInterceptor(token string, guardedMethods []string) grpc.UnaryServerInterceptor {
	guarded := methodSet(guardedMethods)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if token == "" || !guarded[info.FullMethod] {
			return handler(ctx, req)
		}
		if err := verifyToken(ctx, token); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that rejects
// streams to the listed methods when the required shared secret is missing
// or does not match. When token is empty the interceptor is a no-op.
func StreamServerInterceptor(token string, guardedMethods []string) grpc.StreamServerInterceptor {
	guarded := methodSet(guardedMethods)
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if token == "" || !guarded[info.FullMethod] {
			return handler(srv, ss)
		}
		if err := verifyToken(ss.Context(), token); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func methodSet(methods []string) map[string]bool {
	m := make(map[string]bool, len(methods))
	for _, name := range methods {
		m[name] = true
	}
	return m
}

func verifyToken(ctx context.Context, expected string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing scheduler auth token")
	}
	values := md.Get(AuthTokenMetadataKey)
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing scheduler auth token")
	}
	// constantTimeEqual-style check: short-circuit on length mismatch but
	// compare all bytes otherwise to avoid trivial timing side-channels on
	// the shared secret.
	provided := values[0]
	if !constantTimeStringEqual(provided, expected) {
		return status.Error(codes.Unauthenticated, "invalid scheduler auth token")
	}
	return nil
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
