// Package fakeauth provides middlewares thats injects a fake userID, so the rest of the code
// can continue to be multitenant.
package fakeauth

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/weaveworks/common/middleware"
	"github.com/weaveworks/common/server"
	"github.com/weaveworks/common/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ClusterAuthTokenMetadataKey is the gRPC metadata key used to carry the
// shared cluster-internal bearer token on RPCs that multiplex many tenants
// (e.g. scheduler/frontend/querier control-plane loops). Keys are
// case-insensitive on the wire; this value is already lowercase.
const ClusterAuthTokenMetadataKey = "x-cortex-cluster-authorization"

// SetupAuthMiddleware for the given server config.
//
// noGRPCAuthOn lists gRPC fully-qualified method names that MUST NOT run the
// per-request X-Scope-OrgID interceptor, because a single stream multiplexes
// many tenants (scheduler/frontend/querier control-plane loops) or has no
// user at all (health check). Those methods are a sensitive cluster-internal
// surface: without any peer authentication, any party with network reach can
// register as a querier and receive queued queries belonging to arbitrary
// tenants. When clusterAuthToken is non-empty, the returned gRPC interceptors
// require incoming RPCs to one of those exempted methods to present a
// matching token in the ClusterAuthTokenMetadataKey metadata header; RPCs
// missing or mismatching the token are rejected with Unauthenticated.
// When clusterAuthToken is empty, no token is required (preserves historical
// behavior for operators who protect the gRPC listener externally, e.g. mTLS
// or network scoping).
func SetupAuthMiddleware(config *server.Config, enabled bool, noGRPCAuthOn []string, clusterAuthToken string) middleware.Interface {
	if enabled {
		ignoredMethods := map[string]bool{}
		for _, m := range noGRPCAuthOn {
			ignoredMethods[m] = true
		}

		config.GRPCMiddleware = append(config.GRPCMiddleware, func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
			if ignoredMethods[info.FullMethod] {
				if err := verifyClusterAuthToken(ctx, clusterAuthToken); err != nil {
					return nil, err
				}
				return handler(ctx, req)
			}
			return middleware.ServerUserHeaderInterceptor(ctx, req, info, handler)
		})

		config.GRPCStreamMiddleware = append(config.GRPCStreamMiddleware,
			func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
				if ignoredMethods[info.FullMethod] {
					if err := verifyClusterAuthToken(ss.Context(), clusterAuthToken); err != nil {
						return err
					}
					return handler(srv, ss)
				}
				return middleware.StreamServerUserHeaderInterceptor(srv, ss, info, handler)
			},
		)

		return middleware.AuthenticateUser
	}

	config.GRPCMiddleware = append(config.GRPCMiddleware,
		fakeGRPCAuthUniaryMiddleware,
	)
	config.GRPCStreamMiddleware = append(config.GRPCStreamMiddleware,
		fakeGRPCAuthStreamMiddleware,
	)
	return fakeHTTPAuthMiddleware
}

// verifyClusterAuthToken enforces a shared cluster bearer token on gRPC methods
// that are exempted from the per-request tenant-header interceptor. If no token
// is configured it is a no-op, preserving back-compat for deployments that
// authenticate the internal gRPC listener externally (e.g. mTLS / network ACLs).
func verifyClusterAuthToken(ctx context.Context, expected string) error {
	if expected == "" {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing cluster authorization metadata")
	}
	values := md.Get(ClusterAuthTokenMetadataKey)
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing cluster authorization token")
	}
	// Constant-time compare over the first value only: additional values are
	// treated as attacker-controlled noise and ignored.
	if subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid cluster authorization token")
	}
	return nil
}

// WithClusterAuthToken returns ctx augmented with outgoing gRPC metadata that
// carries the cluster-internal bearer token. If token is empty, ctx is returned
// unchanged. Intended for use by legitimate Cortex internal clients
// (querier/worker, frontend v2) when dialing scheduler/frontend control-plane
// loop methods.
func WithClusterAuthToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, ClusterAuthTokenMetadataKey, token)
}

var fakeHTTPAuthMiddleware = middleware.Func(func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := user.InjectOrgID(r.Context(), "fake")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
})

var fakeGRPCAuthUniaryMiddleware = func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx = user.InjectOrgID(ctx, "fake")
	return handler(ctx, req)
}

var fakeGRPCAuthStreamMiddleware = func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := user.InjectOrgID(ss.Context(), "fake")
	return handler(srv, serverStream{
		ctx:          ctx,
		ServerStream: ss,
	})
}

type serverStream struct {
	ctx context.Context
	grpc.ServerStream
}

func (ss serverStream) Context() context.Context {
	return ss.ctx
}
