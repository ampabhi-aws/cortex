package tripperware

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/thanos-io/thanos/pkg/querysharding"
	"github.com/thanos-io/thanos/pkg/store/storepb"
	"github.com/weaveworks/common/httpgrpc"

	cquerysharding "github.com/cortexproject/cortex/pkg/querysharding"
	"github.com/cortexproject/cortex/pkg/tenant"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

func ShardByMiddleware(logger log.Logger, limits Limits, merger Merger) Middleware {
	return MiddlewareFunc(func(next Handler) Handler {
		return shardBy{
			next:   next,
			limits: limits,
			merger: merger,
			logger: logger,
		}
	})
}

type shardBy struct {
	next          Handler
	limits        Limits
	logger        log.Logger
	merger        Merger
	queryAnalyzer *querysharding.QueryAnalyzer
}

func (s shardBy) Do(ctx context.Context, r Request) (Response, error) {
	tenantIDs, err := tenant.TenantIDs(ctx)

	if err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, err.Error())
	}

	numShards := validation.SmallestPositiveIntPerTenant(tenantIDs, s.limits.QueryVerticalShardSize)

	if numShards <= 1 {
		return s.next.Do(ctx, r)
	}

	logger := util_log.WithContext(ctx, s.logger)
	analysis, err := s.queryAnalyzer.Analyze(r.GetQuery())
	if err != nil {
		level.Warn(logger).Log("msg", "error analyzing query", "q", r.GetQuery(), "err", err)
	}

	if err != nil || !analysis.IsShardable() {
		return s.next.Do(ctx, r)
	}

	// Only shard queries whose root expression produces a result that can be
	// safely merged across shards. Even when a nested aggregation is shardable,
	// a top-level expression such as scalar(...) or vector(scalar(...)) either
	// cannot be merged (scalar/string result types have no merge path) or
	// collapses the sharding labels so that every shard's samples collide
	// (e.g. vector(scalar(sum by (job)(up))) produces the empty label set in
	// every shard). In both cases we fall back to the un-sharded path.
	if !isRootResultMergeable(r.GetQuery()) {
		level.Debug(logger).Log("msg", "root expression is not safely mergeable across shards; falling back to un-sharded execution", "q", r.GetQuery())
		return s.next.Do(ctx, r)
	}

	reqs := s.shardQuery(logger, numShards, r, analysis)

	reqResps, err := DoRequests(ctx, s.next, reqs, s.limits)
	if err != nil {
		return nil, err
	}

	resps := make([]Response, 0, len(reqResps))
	for _, reqResp := range reqResps {
		resps = append(resps, reqResp.Response)
	}

	return s.merger.MergeResponse(resps...)
}

// isRootResultMergeable reports whether a parsed PromQL expression's root
// produces a result that the per-shard merge logic can combine deterministically.
//
// The merge sinks (instantquery.MergeResponse / queryrange.PrometheusCodec) can
// only combine vector/matrix results and dedupe them by their label set. If the
// root returns a scalar or string the merge path has no way to combine the N
// shard responses; if the root wraps the aggregation in a function that drops
// the sharding labels (vector(), scalar(), absent(), absent_over_time()), the
// shard responses collide on the same label key and one arbitrary shard's
// partial result is kept non-deterministically. In both cases sharding is unsafe
// and we fall back to the un-sharded path.
func isRootResultMergeable(query string) bool {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		// Parse errors are handled downstream; being conservative, do not shard.
		return false
	}
	return rootReturnsMergeableVector(expr)
}

func rootReturnsMergeableVector(node parser.Expr) bool {
	switch n := node.(type) {
	case *parser.ParenExpr:
		return rootReturnsMergeableVector(n.Expr)
	case *parser.StepInvariantExpr:
		return rootReturnsMergeableVector(n.Expr)
	case *parser.UnaryExpr:
		return rootReturnsMergeableVector(n.Expr)
	case *parser.Call:
		// Reject functions whose output drops the sharding labels and would
		// therefore collapse every shard's result onto the same label set.
		if n.Func != nil {
			switch n.Func.Name {
			case "vector", "scalar", "absent", "absent_over_time":
				return false
			}
			// Also reject calls whose return type is not vector/matrix: those
			// cannot be merged by the vector/matrix merge paths.
			if n.Func.ReturnType != parser.ValueTypeVector && n.Func.ReturnType != parser.ValueTypeMatrix {
				return false
			}
		}
		return true
	}

	// For every other root (AggregateExpr, BinaryExpr, VectorSelector,
	// MatrixSelector, SubqueryExpr, NumberLiteral, StringLiteral, ...) the
	// Prometheus parser already encodes the result type via Type(). Only vector
	// and matrix outputs can be merged across shards; scalar and string outputs
	// have no merge path and would surface as HTTP 500s from the merge sink.
	t := node.Type()
	return t == parser.ValueTypeVector || t == parser.ValueTypeMatrix
}

func (s shardBy) shardQuery(l log.Logger, numShards int, r Request, analysis querysharding.QueryAnalysis) []Request {
	reqs := make([]Request, numShards)
	for i := 0; i < numShards; i++ {
		q, err := cquerysharding.InjectShardingInfo(r.GetQuery(), &storepb.ShardInfo{
			TotalShards: int64(numShards),
			ShardIndex:  int64(i),
			By:          analysis.ShardBy(),
			Labels:      analysis.ShardingLabels(),
		})
		reqs[i] = r.WithQuery(q)

		if err != nil {
			level.Warn(l).Log("msg", "error sharding query", "q", r.GetQuery(), "err", err)
			return []Request{r}
		}
	}

	return reqs
}
