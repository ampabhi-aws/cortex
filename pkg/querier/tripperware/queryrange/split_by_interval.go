package queryrange

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/querier/tripperware"
)

type IntervalFn func(r tripperware.Request) time.Duration

// SplitByIntervalMiddleware creates a new Middleware that splits requests by a given interval.
func SplitByIntervalMiddleware(interval IntervalFn, limits tripperware.Limits, merger tripperware.Merger, registerer prometheus.Registerer) tripperware.Middleware {
	return tripperware.MiddlewareFunc(func(next tripperware.Handler) tripperware.Handler {
		return splitByInterval{
			next:     next,
			limits:   limits,
			merger:   merger,
			interval: interval,
			splitByCounter: promauto.With(registerer).NewCounter(prometheus.CounterOpts{
				Namespace: "cortex",
				Name:      "frontend_split_queries_total",
				Help:      "Total number of underlying query requests after the split by interval is applied",
			}),
		}
	})
}

type splitByInterval struct {
	next     tripperware.Handler
	limits   tripperware.Limits
	merger   tripperware.Merger
	interval IntervalFn

	// Metrics.
	splitByCounter prometheus.Counter
}

func (s splitByInterval) Do(ctx context.Context, r tripperware.Request) (tripperware.Response, error) {
	// First we're going to build new requests, one for each day, taking care
	// to line up the boundaries with step.
	reqs, err := splitQuery(r, s.interval(r))
	if err != nil {
		return nil, err
	}
	s.splitByCounter.Add(float64(len(reqs)))

	reqResps, err := tripperware.DoRequests(ctx, s.next, reqs, s.limits)
	if err != nil {
		return nil, err
	}

	resps := make([]tripperware.Response, 0, len(reqResps))
	for _, reqResp := range reqResps {
		resps = append(resps, reqResp.Response)
	}

	response, err := s.merger.MergeResponse(resps...)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func splitQuery(r tripperware.Request, interval time.Duration) ([]tripperware.Request, error) {
	// If Start == end we should just run the original request
	if r.GetStart() == r.GetEnd() {
		return []tripperware.Request{r}, nil
	}

	// Replace @ modifier function to their respective constant values in the query.
	// This way subqueries will be evaluated at the same time as the parent query.
	query, err := evaluateAtModifierFunction(r.GetQuery(), r.GetStart(), r.GetEnd())
	if err != nil {
		return nil, err
	}
	var reqs []tripperware.Request
	for start := r.GetStart(); start < r.GetEnd(); start = nextIntervalBoundary(start, r.GetStep(), interval) + r.GetStep() {
		end := nextIntervalBoundary(start, r.GetStep(), interval)
		if end+r.GetStep() >= r.GetEnd() {
			end = r.GetEnd()
		}

		reqs = append(reqs, r.WithQuery(query).WithStartEnd(start, end))
	}
	return reqs, nil
}

// maxQueryExpressionDepth bounds the AST nesting depth we accept in the
// query-frontend, as a last line of defense against pathological, deeply
// nested PromQL expressions that make recursive AST walks and the recursive
// pretty-printer quadratic in nesting depth. The limit is intentionally much
// larger than any realistic query: a reasonable manually authored query is a
// few tens of levels deep, and generated queries very rarely exceed a few
// hundred.
const maxQueryExpressionDepth = 10_000

// evaluateAtModifierFunction parse the query and evaluates the `start()` and `end()` at modifier functions into actual constant timestamps.
// For example given the start of the query is 10.00, `http_requests_total[1h] @ start()` query will be replaced with `http_requests_total[1h] @ 10.00`
// If the modifier is already a constant, it will be returned as is.
func evaluateAtModifierFunction(query string, start, end int64) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", httpgrpc.Errorf(http.StatusBadRequest, "%s", err)
	}
	// Walk the AST once:
	//   * reject the request if nesting depth exceeds maxQueryExpressionDepth
	//     (so we never hand a pathological expression to the recursive
	//     printer below);
	//   * replace any `@ start()` / `@ end()` modifier with its constant
	//     timestamp;
	//   * remember whether we actually rewrote anything so we can skip the
	//     quadratic `expr.String()` re-serialization when the expression
	//     contains no start()/end() modifier.
	var rewritten bool
	var depthErr error
	parser.Inspect(expr, func(n parser.Node, path []parser.Node) error {
		if len(path) > maxQueryExpressionDepth {
			depthErr = httpgrpc.Errorf(http.StatusBadRequest, "query expression nesting depth exceeds the maximum of %d", maxQueryExpressionDepth)
			return depthErr
		}
		if selector, ok := n.(*parser.VectorSelector); ok {
			switch selector.StartOrEnd {
			case parser.START:
				selector.Timestamp = &start
				rewritten = true
			case parser.END:
				selector.Timestamp = &end
				rewritten = true
			}
			selector.StartOrEnd = 0
		}
		return nil
	})
	if depthErr != nil {
		return "", depthErr
	}
	// If the expression contains no start()/end() modifier there is nothing to
	// rewrite, so return the original query string and avoid the recursive
	// `expr.String()` printer whose per-level fmt.Sprintf makes
	// re-serialization quadratic in nesting depth.
	if !rewritten {
		return query, nil
	}
	return expr.String(), nil
}

// Round up to the step before the next interval boundary.
func nextIntervalBoundary(t, step int64, interval time.Duration) int64 {
	msPerInterval := int64(interval / time.Millisecond)
	startOfNextInterval := ((t / msPerInterval) + 1) * msPerInterval
	// ensure that target is a multiple of steps away from the start time
	target := startOfNextInterval - ((startOfNextInterval - t) % step)
	if target == startOfNextInterval {
		target -= step
	}
	return target
}
