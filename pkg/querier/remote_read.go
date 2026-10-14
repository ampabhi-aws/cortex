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

// maxRemoteReadQueries caps the number of sub-queries that a single remote
// read request is allowed to carry. Even though the request body is already
// bounded to maxRemoteReadQuerySize bytes (decompressed), individual
// QueryRequest entries are small enough that a 1 MiB body can hold tens or
// hundreds of thousands of entries. Each sub-query fans out to every
// ingester and store-gateway, so we refuse requests whose fan-out is clearly
// outside the Prometheus remote-read protocol's reasonable use.
const maxRemoteReadQueries = 100

// maxRemoteReadQueryParallelism bounds the number of sub-queries that are
// executed concurrently inside a single remote read request. It prevents a
// single request from monopolising goroutines, ingester streams and
// store-gateway slots on the querier.
const maxRemoteReadQueryParallelism = 10

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

		// Reject requests whose fan-out is unreasonably large before starting
		// any work. A single remote read request should not expand into more
		// than a handful of storage queries.
		if len(req.Queries) > maxRemoteReadQueries {
			err := fmt.Errorf("too many queries in remote read request: %d, limit: %d", len(req.Queries), maxRemoteReadQueries)
			level.Warn(logger).Log("msg", "rejecting remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Fetch samples for all queries in parallel, but with a bounded worker
		// pool so a single request cannot create unbounded goroutines or fan
		// out to every ingester/store-gateway without any throttling.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(maxRemoteReadQueryParallelism)
		for i, qr := range req.Queries {
			i, qr := i, qr
			g.Go(func() error {
				from, to, matchers, err := client.FromQueryRequest(qr)
				if err != nil {
					return err
				}
				// Require at least one label matcher. An unrestricted Select
				// invites arbitrarily large fan-outs for essentially no work
				// on the caller side, which is the shape that drives the DoS.
				if len(matchers) == 0 {
					return fmt.Errorf("remote read query must contain at least one label matcher")
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
