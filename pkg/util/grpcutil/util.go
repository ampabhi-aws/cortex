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
// alongside HTTPHeaderPropagationClientInterceptor.
//
// Deprecated: this signature does not apply the configured allowlist against
// the caller-supplied forwarded-logging metadata, which lets a gRPC-reachable
// client inject arbitrary structured-log fields. Prefer
// MakeHTTPHeaderPropagationServerInterceptor, which closes over the allowed
// header names.
func HTTPHeaderPropagationServerInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	ctx = extractForwardedHeadersFromMetadata(ctx, nil)
	h, err := handler(ctx, req)
	return h, err
}

// HTTPHeaderPropagationStreamServerInterceptor does the same as HTTPHeaderPropagationServerInterceptor but for streams.
//
// Deprecated: see HTTPHeaderPropagationServerInterceptor.
func HTTPHeaderPropagationStreamServerInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, wrappedServerStream{
		ctx:          extractForwardedHeadersFromMetadata(ss.Context(), nil),
		ServerStream: ss,
	})
}

// MakeHTTPHeaderPropagationServerInterceptor builds a unary interceptor that
// decodes the caller-supplied forwarded-logging gRPC metadata into the
// request-logging header map on the context, re-applying the configured
// HTTP-side allowlist so that only pre-approved header names can reach the
// log pipeline or be re-emitted as real HTTP headers downstream.
func MakeHTTPHeaderPropagationServerInterceptor(allowed []string) grpc.UnaryServerInterceptor {
	allowedCopy := append([]string(nil), allowed...)
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		ctx = extractForwardedHeadersFromMetadata(ctx, allowedCopy)
		h, err := handler(ctx, req)
		return h, err
	}
}

// MakeHTTPHeaderPropagationStreamServerInterceptor is the stream equivalent of
// MakeHTTPHeaderPropagationServerInterceptor.
func MakeHTTPHeaderPropagationStreamServerInterceptor(allowed []string) grpc.StreamServerInterceptor {
	allowedCopy := append([]string(nil), allowed...)
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, wrappedServerStream{
			ctx:          extractForwardedHeadersFromMetadata(ss.Context(), allowedCopy),
			ServerStream: ss,
		})
	}
}

// extractForwardedHeadersFromMetadata implements HTTPHeaderPropagationServerInterceptor by placing forwarded
// headers into incoming context. When allowed is non-nil, only header names
// in that allowlist survive; otherwise (legacy callers) the whole map is
// forwarded.
func extractForwardedHeadersFromMetadata(ctx context.Context, allowed []string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	if allowed == nil {
		return util_log.ContextWithHeaderMapFromMetadata(ctx, md)
	}
	return util_log.ContextWithHeaderMapFromMetadata(ctx, md, allowed...)
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
