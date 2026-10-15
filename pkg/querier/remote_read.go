package querier

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/storage"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries is the hard cap on the number of sub-queries
// one remote-read request can carry. A 1 MiB decoded body still permits
// tens of thousands of near-empty sub-queries, each of which would otherwise
// trigger a full fan-out to ingesters/store-gateways and allocate its own
// per-query limiter budget. Keep this small — real remote-read clients
// only ever send a handful of queries per request.
const maxRemoteReadQueries = 100

// remoteReadQueryParallelism bounds how many sub-queries of a single
// remote-read request can execute concurrently against the queryable.
// This mirrors the default -querier.max-query-parallelism (14) and
// prevents a single authenticated request from launching an unbounded
// number of goroutines, each performing a full ingester/store-gateway
// fan-out.
const remoteReadQueryParallelism = 14

// RemoteReadHandler handles Prometheus remote read requests.
func RemoteReadHandler(q storage.Queryable, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var req client.ReadRequest
		logger := util_log.WithContext(r.Context(), logger)
		if err := util.ParseProtoReader(ctx, r.Body, int(r.ContentLength), maxRemoteReadQuerySize, &req, util.RawSnappy); err != nil {
			level.Error(logger).Log("msg", "failed to parse proto", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Reject requests whose sub-query count exceeds a small constant to
		// prevent fan-out amplification against ingesters and store-gateways.
		if len(req.Queries) > maxRemoteReadQueries {
			err := fmt.Errorf("too many queries in remote read request: %d > %d", len(req.Queries), maxRemoteReadQueries)
			level.Warn(logger).Log("msg", "rejecting remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Fetch samples for all queries in parallel, but bound the number of
		// in-flight sub-queries so a single request can't exhaust CPU, memory
		// or downstream connections. Each sub-query also closes its querier
		// on completion so per-sub-query resources are released promptly.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		parallelism := remoteReadQueryParallelism
		if parallelism > len(req.Queries) {
			parallelism = len(req.Queries)
		}
		// Buffered so goroutines don't block on send if the collector returns
		// early (e.g. request cancellation).
		errors := make(chan error, len(req.Queries))
		tasks := make(chan int, len(req.Queries))
		for i := range req.Queries {
			tasks <- i
		}
		close(tasks)

		var wg sync.WaitGroup
		wg.Add(parallelism)
		for p := 0; p < parallelism; p++ {
			go func() {
				defer wg.Done()
				for i := range tasks {
					errors <- processRemoteReadQuery(ctx, q, req.Queries[i], i, resp.Results)
				}
			}()
		}
		wg.Wait()
		close(errors)

		var lastErr error
		for err := range errors {
			if err != nil {
				lastErr = err
			}
		}
		if lastErr != nil {
			http.Error(w, lastErr.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Add("Content-Type", "application/x-protobuf")
		if err := util.SerializeProtoResponse(w, &resp, util.RawSnappy); err != nil {
			level.Error(logger).Log("msg", "error sending remote read response", "err", err)
		}
	})
}

// processRemoteReadQuery runs a single remote-read sub-query and stores its
// result at results[i]. The storage.Querier is closed before returning so
// per-sub-query resources held by the distributor/blocks-store queriers are
// released promptly instead of accumulating until the whole request ends.
func processRemoteReadQuery(ctx context.Context, q storage.Queryable, qr *client.QueryRequest, i int, results []*client.QueryResponse) error {
	from, to, matchers, err := client.FromQueryRequest(qr)
	if err != nil {
		return err
	}

	querier, err := q.Querier(ctx, int64(from), int64(to))
	if err != nil {
		return err
	}
	defer querier.Close()

	params := &storage.SelectHints{
		Start: int64(from),
		End:   int64(to),
	}
	seriesSet := querier.Select(false, params, matchers...)
	result, err := seriesSetToQueryResponse(seriesSet)
	if err != nil {
		return err
	}
	results[i] = result
	return nil
}

func seriesSetToQueryResponse(s storage.SeriesSet) (*client.QueryResponse, error) {
	result := &client.QueryResponse{}

	for s.Next() {
		series := s.At()
		samples := []cortexpb.Sample{}
		it := series.Iterator()
		for it.Next() {
			t, v := it.At()
			samples = append(samples, cortexpb.Sample{
				TimestampMs: t,
				Value:       v,
			})
		}
		if err := it.Err(); err != nil {
			return nil, err
		}
		result.Timeseries = append(result.Timeseries, cortexpb.TimeSeries{
			Labels:  cortexpb.FromLabelsToLabelAdapters(series.Labels()),
			Samples: samples,
		})
	}

	return result, s.Err()
}
