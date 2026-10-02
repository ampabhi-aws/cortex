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

// DoRequests executes a list of requests in parallel. The limits parameters is used to limit parallelism per single request.
func DoRequests(ctx context.Context, downstream Handler, reqs []Request, limits Limits) ([]RequestResponse, error) {
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, httpgrpc.Errorf(http.StatusBadRequest, err.Error())
	}

	// If one of the requests fail, we want to be able to cancel the rest of them.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Feed all requests to a bounded intermediate channel to limit parallelism.
	intermediate := make(chan Request)
	go func() {
		defer close(intermediate)
		for _, req := range reqs {
			select {
			case intermediate <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	respChan, errChan := make(chan RequestResponse), make(chan error)
	parallelism := validation.SmallestPositiveIntPerTenant(tenantIDs, limits.MaxQueryParallelism)
	// Guard against non-positive parallelism (e.g. an operator setting
	// `max_query_parallelism: 0` in runtime config). Without this clamp no
	// worker goroutines would be started and the feeder/collector would block
	// forever on their channels.
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > len(reqs) {
		parallelism = len(reqs)
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for req := range intermediate {
				resp, err := downstream.Do(ctx, req)
				if err != nil {
					select {
					case errChan <- err:
					case <-ctx.Done():
						return
					}
				} else {
					select {
					case respChan <- RequestResponse{req, resp}:
					case <-ctx.Done():
						return
					}
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
		case <-ctx.Done():
			return resps, ctx.Err()
		}
	}

	return resps, firstErr
}
