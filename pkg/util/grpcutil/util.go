package grpcutil

import (
	"context"

	"github.com/gogo/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

type wrappedServerStream struct {
	ctx context.Context
	grpc.ServerStream
}

func (ss wrappedServerStream) Context() context.Context {
	return ss.ctx
}

// IsGRPCContextCanceled returns whether the input error is a GRPC error wrapping
// the context.Canceled error.
func IsGRPCContextCanceled(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	return s.Code() == codes.Canceled
}

// HTTPHeaderPropagationServerInterceptor allows for propagation of HTTP Request headers across gRPC calls - works
// alongside HTTPHeaderPropagationClientInterceptor. The returned interceptor
// is a thin shim that applies the operator-configured allowlist to incoming
// metadata; keep it as a free function (ignoring the server-side allowlist)
// for backward compatibility with external callers that may already have
// referenced it.
func HTTPHeaderPropagationServerInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	ctx = extractForwardedHeadersFromMetadata(ctx, nil)
	h, err := handler(ctx, req)
	return h, err
}

// HTTPHeaderPropagationStreamServerInterceptor does the same as HTTPHeaderPropagationServerInterceptor but for streams.
func HTTPHeaderPropagationStreamServerInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, wrappedServerStream{
		ctx:          extractForwardedHeadersFromMetadata(ss.Context(), nil),
		ServerStream: ss,
	})
}

// NewHTTPHeaderPropagationServerInterceptor builds a unary server interceptor
// that only propagates headers whose names are present in the supplied
// operator-configured allowlist.
func NewHTTPHeaderPropagationServerInterceptor(allowlist []string) grpc.UnaryServerInterceptor {
	// Defensive copy so later mutations of the config slice cannot change
	// our view of the allowlist.
	copied := append([]string(nil), allowlist...)
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx = extractForwardedHeadersFromMetadata(ctx, copied)
		return handler(ctx, req)
	}
}

// NewHTTPHeaderPropagationStreamServerInterceptor builds a stream server
// interceptor equivalent to NewHTTPHeaderPropagationServerInterceptor.
func NewHTTPHeaderPropagationStreamServerInterceptor(allowlist []string) grpc.StreamServerInterceptor {
	copied := append([]string(nil), allowlist...)
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, wrappedServerStream{
			ctx:          extractForwardedHeadersFromMetadata(ss.Context(), copied),
			ServerStream: ss,
		})
	}
}

// extractForwardedHeadersFromMetadata implements HTTPHeaderPropagationServerInterceptor by placing forwarded
// headers into incoming context. Only entries whose keys appear in allowlist
// (case-insensitively) are retained.
func extractForwardedHeadersFromMetadata(ctx context.Context, allowlist []string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	return util_log.ContextWithHeaderMapFromMetadata(ctx, md, allowlist)
}

// HTTPHeaderPropagationClientInterceptor allows for propagation of HTTP Request headers across gRPC calls - works
// alongside HTTPHeaderPropagationServerInterceptor
func HTTPHeaderPropagationClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx = injectForwardedHeadersIntoMetadata(ctx)
	return invoker(ctx, method, req, reply, cc, opts...)
}

// HTTPHeaderPropagationStreamClientInterceptor does the same as HTTPHeaderPropagationClientInterceptor but for streams
func HTTPHeaderPropagationStreamClientInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string,
	streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	ctx = injectForwardedHeadersIntoMetadata(ctx)
	return streamer(ctx, desc, cc, method)
}

// injectForwardedHeadersIntoMetadata implements HTTPHeaderPropagationClientInterceptor and HTTPHeaderPropagationStreamClientInterceptor
// by inserting headers that are supposed to be forwarded into metadata of the request
func injectForwardedHeadersIntoMetadata(ctx context.Context) context.Context {
	headerMap := util_log.HeaderMapFromContext(ctx)
	if headerMap == nil {
		return ctx
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(map[string]string{})
	}

	newCtx := ctx
	if _, ok := md[util_log.HeaderPropagationStringForRequestLogging]; !ok {
		var mdContent []string
		for header, content := range headerMap {
			mdContent = append(mdContent, header, content)
		}
		md = md.Copy()
		md[util_log.HeaderPropagationStringForRequestLogging] = mdContent
		newCtx = metadata.NewOutgoingContext(ctx, md)
	}
	return newCtx
}
