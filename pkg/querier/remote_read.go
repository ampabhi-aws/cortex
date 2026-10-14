package querier

import (
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/storage"
	"golang.org/x/sync/errgroup"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/limiter"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries bounds how many sub-queries a single remote-read request
// may fan out into. Prometheus' own remote-read handler serves one query at a
// time; a small cap here keeps the amplification per request bounded and
// prevents a single tenant request from spawning tens of thousands of
// concurrent sub-queries / goroutines / downstream gRPC streams.
const maxRemoteReadQueries = 100

// maxRemoteReadConcurrency bounds how many of a request's sub-queries may run
// in parallel. It replaces the previous unbounded `go func` fan-out.
const maxRemoteReadConcurrency = 10

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

		// Validate the request before doing any work: reject payloads that
		// request an unreasonable number of sub-queries, and reject empty or
		// matcher-less sub-queries that would otherwise force a full index scan
		// on the ingesters / store-gateways.
		if len(req.Queries) == 0 {
			http.Error(w, "no queries in remote read request", http.StatusBadRequest)
			return
		}
		if len(req.Queries) > maxRemoteReadQueries {
			http.Error(w, "too many queries in remote read request", http.StatusBadRequest)
			return
		}
		for _, qr := range req.Queries {
			if qr == nil || len(qr.Matchers) == 0 {
				http.Error(w, "remote read query is missing matchers", http.StatusBadRequest)
				return
			}
		}

		// Install a request-scoped shared QueryLimiter provider so that every
		// sub-query made under this request shares a single QueryLimiter.
		// Without this each sub-query would get a fresh limiter and the
		// per-query series / chunk / byte budgets would be multiplied by the
		// number of sub-queries.
		ctx = limiter.AddSharedQueryLimiterProviderToContext(ctx)

		// Fetch samples for all queries using a bounded worker pool.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(maxRemoteReadConcurrency)
		for i, qr := range req.Queries {
			i, qr := i, qr
			g.Go(func() error {
				from, to, matchers, err := client.FromQueryRequest(qr)
				if err != nil {
					return err
				}

				querier, err := q.Querier(gctx, int64(from), int64(to))
				if err != nil {
					return err
				}

				params := &storage.SelectHints{
					Start: int64(from),
					End:   int64(to),
				}
				seriesSet := querier.Select(false, params, matchers...)
				result, err := seriesSetToQueryResponse(seriesSet)
				if err != nil {
					return err
				}
				resp.Results[i] = result
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
