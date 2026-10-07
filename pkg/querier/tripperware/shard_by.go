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

	// Divide the per-request parallelism budget evenly across shards so that
	// `MaxQueryParallelism` remains an upper bound on the total number of
	// in-flight downstream requests per user request, even when the nested
	// `DoRequests` inside each split sub-request would otherwise consume a
	// fresh budget of MaxQueryParallelism per shard.
	reqResps, err := DoRequests(ctx, s.next, reqs, scaledParallelismLimits{Limits: s.limits, divisor: numShards})
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

// scaledParallelismLimits wraps a Limits so that MaxQueryParallelism is
// divided by `divisor` (floored at 1). It is used by shardBy to split the
// per-request parallelism budget evenly across its shards, so the configured
// `-querier.max-query-parallelism` remains an actual upper bound on the
// total number of in-flight downstream requests, instead of being multiplied
// by the number of shards via the nested DoRequests call.
type scaledParallelismLimits struct {
	Limits
	divisor int
}

func (l scaledParallelismLimits) MaxQueryParallelism(userID string) int {
	p := l.Limits.MaxQueryParallelism(userID)
	if l.divisor <= 1 {
		return p
	}
	if p <= 0 {
		return p
	}
	scaled := p / l.divisor
	if scaled < 1 {
		return 1
	}
	return scaled
}
