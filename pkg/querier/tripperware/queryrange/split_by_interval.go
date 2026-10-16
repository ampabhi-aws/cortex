package queryrange

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/querier/tripperware"
)

// maxSplitByIntervalSubRequests is a safety upper bound on the number of
// sub-requests produced by splitQuery for a single incoming query_range
// request. Even with the smallest supported split interval of 1 minute, a
// legitimate query that spans more than ~190 years cannot exceed this bound,
// so hitting it indicates either a tenant-crafted step value that causes the
// loop to wrap around int64 (CWE-190) or an otherwise pathological input.
// Reaching this cap aborts the split with HTTP 400 instead of letting the
// query-frontend allocate an unbounded slice of sub-requests and OOM the
// shared process.
const maxSplitByIntervalSubRequests = 100000

var errTooManyQuerySplits = httpgrpc.Errorf(
	http.StatusBadRequest,
	"the query would be split into more than %d sub-requests. Please reduce the time range, increase the step, or increase -querier.split-queries-by-interval.",
	maxSplitByIntervalSubRequests,
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
	step := r.GetStep()
	for start := r.GetStart(); start < r.GetEnd(); {
		end := nextIntervalBoundary(start, step, interval)
		if end+step >= r.GetEnd() || end+step < end {
			end = r.GetEnd()
		}

		reqs = append(reqs, r.WithQuery(query).WithStartEnd(start, end))

		// Bound the number of produced sub-requests so a single request cannot
		// drive unbounded allocation in the shared query-frontend.
		if len(reqs) > maxSplitByIntervalSubRequests {
			return nil, errTooManyQuerySplits
		}

		// Advance to the next sub-request start with an overflow-safe check.
		// For a tenant-controlled step close to math.MaxInt64, computing
		// `nextIntervalBoundary(start, step, interval) + step` would wrap int64
		// (CWE-190) and the loop would walk the whole int64 range in small
		// decrements instead of terminating. If adding `step` would overflow
		// or fail to advance `start` strictly forward, we're done.
		boundary := nextIntervalBoundary(start, step, interval)
		if step > 0 && boundary > math.MaxInt64-step {
			break
		}
		next := boundary + step
		if next <= start {
			break
		}
		start = next
	}
	return reqs, nil
}

// evaluateAtModifierFunction parse the query and evaluates the `start()` and `end()` at modifier functions into actual constant timestamps.
// For example given the start of the query is 10.00, `http_requests_total[1h] @ start()` query will be replaced with `http_requests_total[1h] @ 10.00`
// If the modifier is already a constant, it will be returned as is.
func evaluateAtModifierFunction(query string, start, end int64) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", httpgrpc.Errorf(http.StatusBadRequest, "%s", err)
	}
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if selector, ok := n.(*parser.VectorSelector); ok {
			switch selector.StartOrEnd {
			case parser.START:
				selector.Timestamp = &start
			case parser.END:
				selector.Timestamp = &end
			}
			selector.StartOrEnd = 0
		}
		return nil
	})
	return expr.String(), err
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
