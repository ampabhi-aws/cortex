// Copyright 2017 David Ackroyd. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_recovery

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryHandlerFunc is a function that recovers from the panic `p` by returning an `error`.
type RecoveryHandlerFunc func(p interface{}) (err error)

// RecoveryHandlerFuncContext is a function that recovers from the panic `p` by returning an `error`.
// The context can be used to extract request scoped metadata and context values.
type RecoveryHandlerFuncContext func(ctx context.Context, p interface{}) (err error)

type recoveryOptions struct {
	recoveryHandlerFunc RecoveryHandlerFuncContext
}

func evaluateOptions(opts []Option) *recoveryOptions {
	optCopy := &recoveryOptions{}
	for _, o := range opts {
		o(optCopy)
	}
	return optCopy
}

// Option represents a functional option for configuring the recovery interceptor.
type Option func(*recoveryOptions)

// WithRecoveryHandler customizes the function for recovering from a panic.
func WithRecoveryHandler(f RecoveryHandlerFunc) Option {
	return func(o *recoveryOptions) {
		o.recoveryHandlerFunc = RecoveryHandlerFuncContext(func(ctx context.Context, p interface{}) error {
			return f(p)
		})
	}
}

// WithRecoveryHandlerContext customizes the function for recovering from a panic. It can access
// the context used in the request.
func WithRecoveryHandlerContext(f RecoveryHandlerFuncContext) Option {
	return func(o *recoveryOptions) {
		o.recoveryHandlerFunc = f
	}
}

func recoverFrom(ctx context.Context, p interface{}, r RecoveryHandlerFuncContext) error {
	if r == nil {
		return status.Errorf(codes.Internal, "%s", p)
	}
	return r(ctx, p)
}
