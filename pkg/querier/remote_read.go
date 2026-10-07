package querier

import (
	"fmt"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/storage"
	"golang.org/x/sync/errgroup"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries bounds the number of sub-queries that can be submitted
// in a single remote-read request. A minimal protobuf-encoded QueryRequest is
// ~30 bytes, so the maxRemoteReadQuerySize body cap alone permits tens of
// thousands of sub-queries, each spawning a full querier/ingester fan-out.
// 100 is well above any realistic Prometheus/remote-read client while still
// providing a hard safety ceiling to prevent fan-out abuse (CWE-770).
const maxRemoteReadQueries = 100

// maxRemoteReadConcurrency bounds the number of sub-queries from a single
// remote-read request that execute in parallel. Each sub-query opens one
// gRPC stream per ingester/store-gateway in the tenant's shard, so capping
// in-flight sub-queries protects shared downstream services.
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

		// Enforce a hard cap on the number of sub-queries so a single request
		// cannot spawn an unbounded number of goroutines, queriers, and
		// ingester/store-gateway fan-outs (CWE-770).
		if len(req.Queries) > maxRemoteReadQueries {
			err := fmt.Errorf("too many queries in remote read request: %d > %d", len(req.Queries), maxRemoteReadQueries)
			level.Warn(logger).Log("msg", "rejecting remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Fetch samples for all queries in parallel, bounded by
		// maxRemoteReadConcurrency to limit concurrent fan-out.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(maxRemoteReadConcurrency)
		for i, qr := range req.Queries {
			i, qr := i, qr
			g.Go(func() error {
				from, to, matchers, err := client.FromQueryRequest(qr)
				if err != nil {
					return err
				}

				querier, err := q.Querier(gCtx, int64(from), int64(to))
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
