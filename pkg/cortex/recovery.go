package cortex

import (
	"context"
	"runtime/debug"

	"github.com/go-kit/log/level"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// recoverPanic turns a recovered panic value into an error and logs the stack.
// It is used by the gRPC recovery interceptors below so a panic in any gRPC
// handler cannot take down the whole Cortex process (grpc-go deliberately does
// not recover handler panics).
func recoverPanic(r interface{}) error {
	stack := debug.Stack()
	level.Error(util_log.Logger).Log("msg", "gRPC handler panic recovered", "panic", r, "stack", string(stack))
	return status.Errorf(codes.Internal, "panic in gRPC handler: %v", r)
}

// GRPCPanicRecoveryUnaryInterceptor recovers panics raised by downstream unary
// gRPC handlers and converts them into a codes.Internal error so the process
// stays up.
func GRPCPanicRecoveryUnaryInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recoverPanic(r)
			resp = nil
		}
	}()
	return handler(ctx, req)
}

// GRPCPanicRecoveryStreamInterceptor recovers panics raised by downstream
// streaming gRPC handlers and converts them into a codes.Internal error so the
// process stays up.
func GRPCPanicRecoveryStreamInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recoverPanic(r)
		}
	}()
	return handler(srv, ss)
}
