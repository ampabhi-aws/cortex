package tripperware

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// RequestResponse contains a request response and the respective request that was used.
type RequestResponse struct {
	Request  Request
	Response Response
}

// parallelismBudget carries the shared per-user-request parallelism budget
// and the total downstream request counter across all nested DoRequests
// calls (split_by_interval, results_cache, shardBy, ...). It is stored in
// the context so every fan-out layer draws from the same pool instead of
// each one allocating its own MaxQueryParallelism goroutines, which
// otherwise multiplies into parallelism^N concurrent downstream queries.
type parallelismBudget struct {
	// slots is the number of worker goroutines still available across all
	// nested DoRequests invocations for the owning user request. It is
	// decremented when workers are spawned and incremented back when they
	// finish. Access only via sync/atomic helpers.
	slots int64
	// total counts the cumulative number of downstream requests dispatched
	// for this user request so we can enforce a hard upper bound on fan-out.
	// Access only via sync/atomic helpers.
	total int64
	// hardCap is the hard cap on the total number of downstream requests
	// permitted for this single user request. Zero disables the cap.
	hardCap int64
}

type parallelismBudgetKey struct{}

// maxDownstreamRequestsMultiplier bounds the total number of downstream
// requests a single user request may issue to this many times the configured
// per-request MaxQueryParallelism. It is deliberately generous so that
// normal workloads (long time ranges split into many sub-queries served
// sequentially through the shared pool) are not affected, while still
// preventing unbounded multiplicative fan-out from nested middlewares.
// Note that query_vertical_shard_size multiplies the work performed per
// split interval, so this cap also protects against pathological
// combinations of split * cache-partition * shard fan-out.
const maxDownstreamRequestsMultiplier = 1000

func newParallelismBudget(n int) *parallelismBudget {
	if n < 1 {
		n = 1
	}
	return &parallelismBudget{
		slots:   int64(n),
		hardCap: int64(n) * maxDownstreamRequestsMultiplier,
	}
}

// reserveWorkers atomically removes up to want worker slots from the shared
// pool and returns how many were granted. The caller MUST return the same
// number via releaseWorkers once its workers have finished.
func (b *parallelismBudget) reserveWorkers(want int) int {
	if want <= 0 {
		return 0
	}
	for {
		cur := atomic.LoadInt64(&b.slots)
		if cur <= 0 {
			return 0
		}
		give := int64(want)
		if give > cur {
			give = cur
		}
		if atomic.CompareAndSwapInt64(&b.slots, cur, cur-give) {
			return int(give)
		}
	}
}

func (b *parallelismBudget) releaseWorkers(n int) {
	if n <= 0 {
		return
	}
	atomic.AddInt64(&b.slots, int64(n))
}

// WithQueryParallelism attaches a shared parallelism budget to ctx so that
// all nested tripperware fan-out layers (split, cache-partition, shard)
// share a single pool of n worker goroutines instead of each creating their
// own fleet. It is safe to call this once at the outermost tripperware
// entry point; DoRequests will create a budget lazily if none is present.
func WithQueryParallelism(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, parallelismBudgetKey{}, newParallelismBudget(n))
}

// DoRequests executes a list of requests in parallel. The parallelism budget
// (max_query_parallelism) is shared across all nested DoRequests invocations
// for the same user request via a worker pool stored in ctx: this prevents
// the product-of-layers concurrency amplification where splitByInterval,
// resultsCache.handleHit and shardBy would each start their own fleet of
// workers. See WithQueryParallelism.
func DoRequests(ctx context.Context, downstream Handler, reqs []Request, limits Limits) ([]RequestResponse, error) {
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, err.Error())
	}

	if len(reqs) == 0 {
		return nil, nil
	}

	// Reuse the shared parallelism budget if one was already installed by
	// an outer middleware; otherwise create one now and propagate it to
	// any nested DoRequests calls through ctx. This makes the limit per
	// user request, not per fan-out layer.
	budget, nested := ctx.Value(parallelismBudgetKey{}).(*parallelismBudget)
	if !nested {
		n := validation.SmallestPositiveIntPerTenant(tenantIDs, limits.MaxQueryParallelism)
		budget = newParallelismBudget(n)
		ctx = context.WithValue(ctx, parallelismBudgetKey{}, budget)
	}

	// Enforce the hard cap on the total number of downstream requests this
	// user request may issue across all nested fan-out layers combined.
	if budget.hardCap > 0 {
		if atomic.AddInt64(&budget.total, int64(len(reqs))) > budget.hardCap {
			return nil, httpgrpc.Errorf(http.StatusTooManyRequests,
				"too many downstream requests for a single user query (cap %d)", budget.hardCap)
		}
	}

	// If one of the requests fail, we want to be able to cancel the rest of them.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Determine how many worker goroutines to run at this layer. We draw
	// from the shared pool so that nested DoRequests calls do not multiply
	// the concurrency. The current goroutine (which runs the collector
	// loop below) also drives work when no extra slot is available, so
	// progress is always possible even if the pool is empty.
	perLayerLimit := validation.SmallestPositiveIntPerTenant(tenantIDs, limits.MaxQueryParallelism)
	if perLayerLimit < 1 {
		perLayerLimit = 1
	}
	desiredExtras := len(reqs) - 1
	if desiredExtras > perLayerLimit-1 {
		desiredExtras = perLayerLimit - 1
	}
	if desiredExtras < 0 {
		desiredExtras = 0
	}
	extraWorkers := budget.reserveWorkers(desiredExtras)
	defer budget.releaseWorkers(extraWorkers)

	// Feed all requests to an intermediate channel. One of the workers is
	// the current goroutine (effectively), running inline when
	// extraWorkers==0 means we fall back to sequential processing in a
	// single goroutine spawned below. We always run the worker in a
	// goroutine so results are collected uniformly through the channels
	// below.
	intermediate := make(chan Request)
	go func() {
		for _, req := range reqs {
			intermediate <- req
		}
		close(intermediate)
	}()

	respChan, errChan := make(chan RequestResponse), make(chan error)
	worker := func() {
		for req := range intermediate {
			resp, werr := downstream.Do(ctx, req)
			if werr != nil {
				errChan <- werr
			} else {
				respChan <- RequestResponse{req, resp}
			}
		}
	}
	// Spawn extraWorkers goroutines plus one "driver" goroutine. The driver
	// guarantees progress even when extraWorkers==0 (pool exhausted by an
	// outer DoRequests invocation): in that case this layer effectively
	// serialises its own requests through a single goroutine, which is
	// precisely what prevents the parallelism^N amplification.
	for i := 0; i < extraWorkers; i++ {
		go worker()
	}
	go worker()

	resps := make([]RequestResponse, 0, len(reqs))
	var firstErr error
	for range reqs {
		select {
		case resp := <-respChan:
			resps = append(resps, resp)
		case werr := <-errChan:
			if firstErr == nil {
				cancel()
				firstErr = werr
			}
		}
	}

	return resps, firstErr
}
