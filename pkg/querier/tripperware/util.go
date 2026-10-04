package tripperware

import (
	"context"
	"net/http"

	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// RequestResponse contains a request response and the respective request that was used.
type RequestResponse struct {
	Request  Request
	Response Response
}

// parallelismSemaphore is a buffered channel used as a counting semaphore to
// enforce a shared, request-scoped cap on the number of concurrent downstream
// invocations made by DoRequests across all nesting levels.
type parallelismSemaphore chan struct{}

// parallelismSemaphoreKey is the context key used to carry the request-scoped
// parallelism semaphore between nested DoRequests invocations.
type parallelismSemaphoreKey struct{}

// DoRequests executes a list of requests in parallel. The limits parameter is used to
// limit the per-tenant parallelism of downstream calls.
//
// The query-range middleware chain nests three fan-out stages (splitByInterval,
// resultsCache and shardBy), each of which calls DoRequests. To prevent the
// configured max_query_parallelism from being multiplied by every stage, the
// outermost DoRequests call installs a request-scoped counting semaphore on the
// context sized at the tenant's effective max_query_parallelism. Every worker,
// regardless of nesting depth, must acquire a slot from this semaphore before
// invoking downstream.Do and release it afterwards, so the number of in-flight
// downstream requests for a single HTTP request is bounded by the configured
// cap rather than the product of per-stage caps.
//
// Nested DoRequests calls release one slot on entry (the caller worker that
// invoked them is parked waiting for them to return and therefore does not
// consume compute) and re-acquire it on exit, which prevents deadlocks when
// every outer worker is simultaneously blocked on a nested fan-out.
func DoRequests(ctx context.Context, downstream Handler, reqs []Request, limits Limits) ([]RequestResponse, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, err.Error())
	}

	// If one of the requests fail, we want to be able to cancel the rest of them.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	parallelism := validation.SmallestPositiveIntPerTenant(tenantIDs, limits.MaxQueryParallelism)
	if parallelism < 1 {
		parallelism = 1
	}

	// Reuse the request-scoped parallelism semaphore installed by the outermost
	// DoRequests call, if any; otherwise create one sized at the tenant's
	// effective max_query_parallelism and install it on the context so nested
	// fan-outs (splitByInterval -> resultsCache -> shardBy) share the same
	// bounded worker budget instead of multiplying it.
	sem, nested := ctx.Value(parallelismSemaphoreKey{}).(parallelismSemaphore)
	if !nested {
		sem = make(parallelismSemaphore, parallelism)
		ctx = context.WithValue(ctx, parallelismSemaphoreKey{}, sem)
	} else {
		// The caller worker that invoked this nested DoRequests is parked
		// waiting for us to return. Release its semaphore slot while we run so
		// our own workers can acquire, and re-acquire it before returning so
		// the caller resumes with a slot held, as it had when it called us.
		// This is required to avoid a deadlock when every outer worker is
		// simultaneously blocked on a nested fan-out.
		select {
		case <-sem:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() {
			// Use the parent context (never Done) to re-acquire; if ctx is
			// Done we still need to restore the invariant for the caller.
			sem <- struct{}{}
		}()
	}

	// Feed all requests to a bounded intermediate channel to limit parallelism.
	intermediate := make(chan Request)
	go func() {
		for _, req := range reqs {
			intermediate <- req
		}
		close(intermediate)
	}()

	workers := parallelism
	if workers > len(reqs) {
		workers = len(reqs)
	}

	respChan, errChan := make(chan RequestResponse), make(chan error)
	for i := 0; i < workers; i++ {
		go func() {
			for req := range intermediate {
				// Acquire a slot from the shared, request-scoped semaphore
				// before issuing the downstream call so the total number of
				// concurrent downstream invocations across all nesting levels
				// is bounded by max_query_parallelism.
				var (
					resp Response
					err  error
				)
				select {
				case sem <- struct{}{}:
					resp, err = downstream.Do(ctx, req)
					<-sem
				case <-ctx.Done():
					err = ctx.Err()
				}
				if err != nil {
					errChan <- err
				} else {
					respChan <- RequestResponse{req, resp}
				}
			}
		}()
	}

	resps := make([]RequestResponse, 0, len(reqs))
	var firstErr error
	for range reqs {
		select {
		case resp := <-respChan:
			resps = append(resps, resp)
		case err := <-errChan:
			if firstErr == nil {
				cancel()
				firstErr = err
			}
		}
	}

	return resps, firstErr
}
