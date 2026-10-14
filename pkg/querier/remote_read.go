package querier

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/storage"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/concurrency"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// maxRemoteReadQueries bounds the number of sub-queries that a single remote
// read request may contain. Prometheus-compatible clients always send exactly
// one query per request, so this is comfortably sized while still preventing
// an attacker from stuffing a (byte-size-bounded) request body with hundreds
// of thousands of empty QueryRequest elements and amplifying it into a
// goroutine / distributed-query storm.
const maxRemoteReadQueries = 100

// maxRemoteReadConcurrency bounds the number of sub-queries from a single
// remote read request that are executed concurrently, replacing the
// previous unbounded `go func` per element pattern.
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

		// Reject requests that contain more sub-queries than we are willing to
		// serve from a single HTTP request. The protobuf ReadRequest schema has
		// no element-count limit on repeated QueryRequest entries and each entry
		// can be as small as 2 bytes on the wire, so without this check an
		// attacker can amplify a small (snappy-compressed) body into hundreds
		// of thousands of concurrent distributed queries.
		if len(req.Queries) > maxRemoteReadQueries {
			err := fmt.Errorf("remote read request contains %d queries, but the maximum allowed per request is %d", len(req.Queries), maxRemoteReadQueries)
			level.Error(logger).Log("msg", "rejecting remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Fetch samples for all queries in parallel, bounding concurrency so a
		// single request cannot spawn an unbounded number of goroutines or
		// in-flight gRPC streams to ingesters / store-gateways.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}
		jobs := make([]interface{}, len(req.Queries))
		for i := range req.Queries {
			jobs[i] = i
		}
		err := concurrency.ForEach(ctx, jobs, maxRemoteReadConcurrency, func(ctx context.Context, job interface{}) error {
			i := job.(int)
			qr := req.Queries[i]

			from, to, matchers, err := client.FromQueryRequest(qr)
			if err != nil {
				return err
			}

			querier, err := q.Querier(ctx, int64(from), int64(to))
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
		if err != nil {
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
