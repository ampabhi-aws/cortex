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

// maxQueryExprDepth caps the maximum PromQL AST nesting depth accepted by the
// query-frontend. The vendored Prometheus parser is recursive, and the
// re-serialisation path used below is quadratic in nesting depth, so an
// extremely deeply-nested expression can allocate hundreds of GB and / or
// drive the goroutine stack past Go's 1 GB cap. A few hundred levels is well
// beyond what any realistic PromQL query uses in practice.
const maxQueryExprDepth = 500

// evaluateAtModifierFunction parse the query and evaluates the `start()` and `end()` at modifier functions into actual constant timestamps.
// For example given the start of the query is 10.00, `http_requests_total[1h] @ start()` query will be replaced with `http_requests_total[1h] @ 10.00`
// If the modifier is already a constant, it will be returned as is.
func evaluateAtModifierFunction(query string, start, end int64) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", httpgrpc.Errorf(http.StatusBadRequest, "%s", err)
	}
	if err := checkASTDepth(expr, maxQueryExprDepth); err != nil {
		return "", err
	}
	hasAtModifier := false
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if selector, ok := n.(*parser.VectorSelector); ok {
			switch selector.StartOrEnd {
			case parser.START:
				selector.Timestamp = &start
				hasAtModifier = true
			case parser.END:
				selector.Timestamp = &end
				hasAtModifier = true
			}
			selector.StartOrEnd = 0
		}
		return nil
	})
	// Avoid the quadratic re-serialisation when the AST has no `start()`/`end()`
	// at-modifier to rewrite - the original query text is already correct.
	if !hasAtModifier {
		return query, nil
	}
	return expr.String(), nil
}

// checkASTDepth walks the parsed expression and returns a bad-request error if
// its nesting depth exceeds maxDepth. The walk itself is bounded by maxDepth,
// so it does not itself risk a stack overflow.
func checkASTDepth(expr parser.Expr, maxDepth int) error {
	var check func(parser.Node, int) error
	check = func(n parser.Node, d int) error {
		if n == nil {
			return nil
		}
		if d > maxDepth {
			return httpgrpc.Errorf(http.StatusBadRequest, "query expression is too deeply nested (max depth %d)", maxDepth)
		}
		for _, c := range parser.Children(n) {
			if err := check(c, d+1); err != nil {
				return err
			}
		}
		return nil
	}
	return check(expr, 1)
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
