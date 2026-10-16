package querier

import (
	"fmt"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/gate"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/limiter"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries is the maximum number of sub-queries allowed in a single
// remote-read request. Prometheus's native remote-read handler fans out one
// goroutine per sub-query behind a concurrency gate, but Cortex sits in front
// of shared ingesters and store-gateways, so a request with tens of thousands
// of sub-queries would otherwise amplify a 1 MiB HTTP body into tens of
// thousands of concurrent gRPC calls to every ingester and store-gateway in
// the tenant's shard. The limit matches the order of magnitude of what a
// Prometheus server configured with the default remote-read concurrency
// would ever send in one body.
const maxRemoteReadQueries = 128

// maxRemoteReadQueryConcurrency bounds the number of sub-queries from a single
// remote-read request that execute concurrently. It mirrors the role of
// Prometheus's -storage.remote.read-concurrent-limit and prevents a single
// authenticated request from spawning an unbounded number of goroutines, each
// of which fans out to every ingester and store-gateway in the tenant's shard.
const maxRemoteReadQueryConcurrency = 10

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

		// Reject requests whose sub-query count would allow a single HTTP
		// request to schedule an unbounded amount of fan-out work.
		if len(req.Queries) > maxRemoteReadQueries {
			err := fmt.Errorf("too many queries in remote read request: %d (limit: %d)", len(req.Queries), maxRemoteReadQueries)
			level.Warn(logger).Log("msg", "rejected remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Attach a single shared QueryLimiter holder to the context so that
		// every sub-query of this HTTP request accounts against the same
		// per-query budget rather than each getting a fresh limiter and
		// effectively multiplying the per-query ceilings by the number of
		// sub-queries.
		ctx, _ = limiter.AddSharedQueryLimiterToContext(ctx)

		// Fetch samples for all queries using a bounded worker pool so a
		// single request cannot spawn arbitrarily many concurrent Select
		// calls on shared ingesters and store-gateways. Cancel outstanding
		// work as soon as the HTTP context is cancelled.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		concurrency := maxRemoteReadQueryConcurrency
		if n := len(req.Queries); n > 0 && n < concurrency {
			concurrency = n
		}
		remoteReadGate := gate.New(concurrency)
		errors := make(chan error, len(req.Queries))
		for i, qr := range req.Queries {
			go func(i int, qr *client.QueryRequest) {
				if err := remoteReadGate.Start(ctx); err != nil {
					errors <- err
					return
				}
				defer remoteReadGate.Done()

				// Abort if the client has gone away or another sub-query has
				// already caused the request to be cancelled.
				if err := ctx.Err(); err != nil {
					errors <- err
					return
				}

				from, to, matchers, err := client.FromQueryRequest(qr)
				if err != nil {
					errors <- err
					return
				}

				querier, err := q.Querier(ctx, int64(from), int64(to))
				if err != nil {
					errors <- err
					return
				}

				params := &storage.SelectHints{
					Start: int64(from),
					End:   int64(to),
				}
				seriesSet := querier.Select(false, params, matchers...)
				resp.Results[i], err = seriesSetToQueryResponse(seriesSet)
				errors <- err
			}(i, qr)
		}

		var lastErr error
		for range req.Queries {
			err := <-errors
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
