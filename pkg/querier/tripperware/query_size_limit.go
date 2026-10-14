package tripperware

import (
	"context"
	"net/http"

	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// QueryExpressionSizeLimitMiddleware rejects requests whose raw PromQL query
// expression exceeds the per-tenant configured maximum size in bytes. The
// check runs before any downstream middleware so that attacker-controlled
// expressions never reach the PromQL parser, AST walker, or re-serialiser,
// each of which can allocate super-linearly in the length and nesting depth
// of the expression. A limit of 0 (or no override) disables the check.
func QueryExpressionSizeLimitMiddleware(limits Limits) Middleware {
	return MiddlewareFunc(func(next Handler) Handler {
		return queryExpressionSizeLimit{
			next:   next,
			limits: limits,
		}
	})
}

type queryExpressionSizeLimit struct {
	next   Handler
	limits Limits
}

func (q queryExpressionSizeLimit) Do(ctx context.Context, r Request) (Response, error) {
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, "%s", err.Error())
	}

	// Pick the smallest positive (most restrictive) non-zero limit across the
	// tenant IDs on the request. 0 means "no limit" for that tenant.
	maxSize := 0
	for _, tenantID := range tenantIDs {
		if size := q.limits.MaxQueryExpressionSizeBytes(tenantID); size > 0 {
			if maxSize == 0 || size < maxSize {
				maxSize = size
			}
		}
	}

	if maxSize > 0 {
		if querySize := len(r.GetQuery()); querySize > maxSize {
			return nil, httpgrpc.Errorf(http.StatusBadRequest, validation.ErrQueryExpressionTooLarge, querySize, maxSize)
		}
	}

	return q.next.Do(ctx, r)
}
