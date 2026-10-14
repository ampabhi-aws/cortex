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
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries bounds the number of sub-queries a single remote read
// request may contain. The Prometheus remote read API itself only ever sends a
// handful of sub-queries per request (one per Querier call), so this limit is
// deliberately small. It exists to prevent a single ~tens-of-KB snappy-encoded
// request from fanning out to tens of thousands of concurrent storage queries
// (CWE-770).
const maxRemoteReadQueries = 100

// maxRemoteReadQueryConcurrency bounds the number of sub-queries from a single
// remote read request that may execute concurrently against the underlying
// Queryable. Together with maxRemoteReadQueries this caps per-request fan-out
// to the ingesters and store-gateways.
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

		// Reject requests whose sub-query count exceeds a small constant. A
		// bounded-size body may still legally contain tens of thousands of
		// tiny QueryRequest entries, which otherwise fan out to as many
		// concurrent storage queries.
		if len(req.Queries) > maxRemoteReadQueries {
			err := "too many queries in remote read request"
			level.Error(logger).Log("msg", err, "queries", len(req.Queries), "limit", maxRemoteReadQueries)
			http.Error(w, err, http.StatusBadRequest)
			return
		}

		// Fetch samples for all queries in parallel, through a bounded worker
		// pool. errgroup.Group.SetLimit caps the number of concurrently
		// running goroutines; errgroup.WithContext cancels the shared context
		// as soon as any sub-query returns an error so the remaining
		// sub-queries stop accumulating results.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(maxRemoteReadQueryConcurrency)
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
