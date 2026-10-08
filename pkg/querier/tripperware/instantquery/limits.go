package instantquery

import (
	"context"
	"net/http"

	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/querier/tripperware"
	"github.com/cortexproject/cortex/pkg/tenant"
)

type limitsMiddleware struct {
	tripperware.Limits
	next tripperware.Handler
}

// NewLimitsMiddleware creates a new Middleware that enforces per-tenant limits on instant queries
// before any downstream middleware parses or walks the PromQL AST.
func NewLimitsMiddleware(l tripperware.Limits) tripperware.Middleware {
	return tripperware.MiddlewareFunc(func(next tripperware.Handler) tripperware.Handler {
		return limitsMiddleware{
			next:   next,
			Limits: l,
		}
	})
}

func (l limitsMiddleware) Do(ctx context.Context, r tripperware.Request) (tripperware.Response, error) {
	if _, err := tenant.TenantIDs(ctx); err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, err.Error())
	}

	// Enforce the max query expression size (in bytes) before any middleware parses the
	// expression. This protects against unbounded PromQL AST depth / size that would otherwise
	// cause fatal stack exhaustion or quadratic CPU in parser.ParseExpr / expr.String().
	if err := tripperware.ValidateQueryExpressionSize(ctx, r.GetQuery(), l.Limits); err != nil {
		return nil, err
	}

	return l.next.Do(ctx, r)
}
