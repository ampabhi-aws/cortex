package limiter

import (
	"context"
	"fmt"
	"sync"

	"github.com/prometheus/common/model"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
)

type queryLimiterCtxKey struct{}
type sharedQueryLimiterProviderCtxKey struct{}

var (
	ctxKey                    = &queryLimiterCtxKey{}
	sharedProviderKey         = &sharedQueryLimiterProviderCtxKey{}
	ErrMaxSeriesHit           = "the query hit the max number of series limit (limit: %d series)"
	ErrMaxChunkBytesHit       = "the query hit the aggregated chunks size limit (limit: %d bytes)"
	ErrMaxDataBytesHit        = "the query hit the aggregated data size limit (limit: %d bytes)"
	ErrMaxChunksPerQueryLimit = "the query hit the max number of chunks limit (limit: %d chunks)"
)

type QueryLimiter struct {
	uniqueSeriesMx sync.Mutex
	uniqueSeries   map[model.Fingerprint]struct{}

	chunkBytesCount atomic.Int64
	dataBytesCount  atomic.Int64
	chunkCount      atomic.Int64

	maxSeriesPerQuery     int
	maxChunkBytesPerQuery int
	maxDataBytesPerQuery  int
	maxChunksPerQuery     int
}

// NewQueryLimiter makes a new per-query limiter. Each query limiter
// is configured using the `maxSeriesPerQuery` limit.
func NewQueryLimiter(maxSeriesPerQuery, maxChunkBytesPerQuery, maxChunksPerQuery, maxDataBytesPerQuery int) *QueryLimiter {
	return &QueryLimiter{
		uniqueSeriesMx: sync.Mutex{},
		uniqueSeries:   map[model.Fingerprint]struct{}{},

		maxSeriesPerQuery:     maxSeriesPerQuery,
		maxChunkBytesPerQuery: maxChunkBytesPerQuery,
		maxChunksPerQuery:     maxChunksPerQuery,
		maxDataBytesPerQuery:  maxDataBytesPerQuery,
	}
}

func AddQueryLimiterToContext(ctx context.Context, limiter *QueryLimiter) context.Context {
	return context.WithValue(ctx, ctxKey, limiter)
}

// SharedQueryLimiterProvider lazily constructs and caches a single QueryLimiter
// that is shared across every sub-query made under one logical request. It lets
// a request-scoped caller (e.g. the remote-read HTTP handler, which performs N
// independent sub-queries) enforce the per-query series/chunk/byte limits over
// the whole request instead of allowing each sub-query to allocate its own
// (unshared) budget.
type SharedQueryLimiterProvider struct {
	once sync.Once
	ql   *QueryLimiter
}

// Get returns the shared QueryLimiter, constructing it exactly once via factory.
func (p *SharedQueryLimiterProvider) Get(factory func() *QueryLimiter) *QueryLimiter {
	p.once.Do(func() {
		p.ql = factory()
	})
	return p.ql
}

// AddSharedQueryLimiterProviderToContext installs a fresh
// SharedQueryLimiterProvider on the context. Downstream code that would
// normally build a fresh per-query limiter should instead ask the provider for
// one via Get so that every sub-query under the same request shares the limits.
func AddSharedQueryLimiterProviderToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, sharedProviderKey, &SharedQueryLimiterProvider{})
}

// SharedQueryLimiterProviderFromContext returns the shared provider installed
// on the context, or nil if none was installed. Callers that get nil must fall
// back to allocating a per-query limiter as before.
func SharedQueryLimiterProviderFromContext(ctx context.Context) *SharedQueryLimiterProvider {
	p, _ := ctx.Value(sharedProviderKey).(*SharedQueryLimiterProvider)
	return p
}

// QueryLimiterFromContextWithFallback returns a QueryLimiter from the current context.
// If there is not a QueryLimiter on the context it will return a new no-op limiter.
func QueryLimiterFromContextWithFallback(ctx context.Context) *QueryLimiter {
	ql, ok := ctx.Value(ctxKey).(*QueryLimiter)
	if !ok {
		// If there's no limiter return a new unlimited limiter as a fallback
		ql = NewQueryLimiter(0, 0, 0, 0)
	}
	return ql
}

// AddSeries adds the input series and returns an error if the limit is reached.
func (ql *QueryLimiter) AddSeries(seriesLabels []cortexpb.LabelAdapter) error {
	// If the max series is unlimited just return without managing map
	if ql.maxSeriesPerQuery == 0 {
		return nil
	}
	fingerprint := client.FastFingerprint(seriesLabels)

	ql.uniqueSeriesMx.Lock()
	defer ql.uniqueSeriesMx.Unlock()

	ql.uniqueSeries[fingerprint] = struct{}{}
	if len(ql.uniqueSeries) > ql.maxSeriesPerQuery {
		// Format error with max limit
		return fmt.Errorf(ErrMaxSeriesHit, ql.maxSeriesPerQuery)
	}
	return nil
}

// uniqueSeriesCount returns the count of unique series seen by this query limiter.
func (ql *QueryLimiter) uniqueSeriesCount() int {
	ql.uniqueSeriesMx.Lock()
	defer ql.uniqueSeriesMx.Unlock()
	return len(ql.uniqueSeries)
}

// AddChunkBytes adds the input chunk size in bytes and returns an error if the limit is reached.
func (ql *QueryLimiter) AddChunkBytes(chunkSizeInBytes int) error {
	if ql.maxChunkBytesPerQuery == 0 {
		return nil
	}
	if ql.chunkBytesCount.Add(int64(chunkSizeInBytes)) > int64(ql.maxChunkBytesPerQuery) {
		return fmt.Errorf(ErrMaxChunkBytesHit, ql.maxChunkBytesPerQuery)
	}
	return nil
}

// AddDataBytes adds the queried data bytes and returns an error if the limit is reached.
func (ql *QueryLimiter) AddDataBytes(dataSizeInBytes int) error {
	if ql.maxDataBytesPerQuery == 0 {
		return nil
	}
	if ql.dataBytesCount.Add(int64(dataSizeInBytes)) > int64(ql.maxDataBytesPerQuery) {
		return fmt.Errorf(ErrMaxDataBytesHit, ql.maxDataBytesPerQuery)
	}
	return nil
}

func (ql *QueryLimiter) AddChunks(count int) error {
	if ql.maxChunksPerQuery == 0 {
		return nil
	}

	if ql.chunkCount.Add(int64(count)) > int64(ql.maxChunksPerQuery) {
		return fmt.Errorf(fmt.Sprintf(ErrMaxChunksPerQueryLimit, ql.maxChunksPerQuery))
	}
	return nil
}
