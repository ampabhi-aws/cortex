package tripperware

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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

func (s shardBy) shardQuery(l log.Logger, numShards int, r Request, analysis querysharding.QueryAnalysis) []Request {
	shardInfos := make([]*storepb.ShardInfo, numShards)
	for i := 0; i < numShards; i++ {
		shardInfos[i] = &storepb.ShardInfo{
			TotalShards: int64(numShards),
			ShardIndex:  int64(i),
			By:          analysis.ShardBy(),
			Labels:      analysis.ShardingLabels(),
		}
	}

	// Parse / print the PromQL exactly once per request (instead of once per shard).
	// Expr.String() is quadratic in AST nesting depth, so sharing the parse
	// bounds the frontend-side work to a single O(n^2) printing cycle per shard
	// instead of per-shard-per-parse.
	queries, err := cquerysharding.InjectShardingInfoBatch(r.GetQuery(), shardInfos)
	if err != nil {
		level.Warn(l).Log("msg", "error sharding query", "q", r.GetQuery(), "err", err)
		return []Request{r}
	}

	reqs := make([]Request, numShards)
	for i, q := range queries {
		reqs[i] = r.WithQuery(q)
	}

	return reqs
}
