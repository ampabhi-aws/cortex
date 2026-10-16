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
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/concurrency"
	"github.com/cortexproject/cortex/pkg/util/limiter"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// Queries are a set of matchers with time ranges - should not get into megabytes
const maxRemoteReadQuerySize = 1024 * 1024

// defaultRemoteReadConcurrency is the fallback number of sub-queries that are
// executed in parallel for a single remote-read HTTP request when the
// configured value is <= 0.
const defaultRemoteReadConcurrency = 10

// RemoteReadHandler handles Prometheus remote read requests.
//
// The handler bounds the work a single HTTP request can request:
//  1. The number of QueryRequest entries in the decoded body is capped by
//     cfg.MaxRemoteReadQueries (0 disables the check).
//  2. Sub-queries are processed by a bounded worker pool
//     (cfg.RemoteReadConcurrency) instead of an unbounded fan-out of
//     goroutines.
//  3. A single QueryLimiter is installed into the request context and reused
//     across every sub-query, so max_fetched_chunks_per_query /
//     max_fetched_series_per_query / max_fetched_data_bytes_per_query bound
//     the whole request rather than each sub-query.
//  4. cfg.Timeout (-querier.timeout) is applied as the request deadline when
//     > 0.
//
// A nil limits argument disables the request-scoped QueryLimiter and falls
// back to the previous per-sub-query behaviour; this preserves callers (e.g.
// unit tests) that do not plumb a validation.Overrides through.
func RemoteReadHandler(cfg Config, q storage.Queryable, limits *validation.Overrides, logger log.Logger) http.Handler {
	maxQueries := cfg.MaxRemoteReadQueries
	readConcurrency := cfg.RemoteReadConcurrency
	if readConcurrency <= 0 {
		readConcurrency = defaultRemoteReadConcurrency
	}
	timeout := cfg.Timeout

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := util_log.WithContext(ctx, logger)

		// Apply -querier.timeout to the whole request. The PromQL engine's
		// own timeout is bypassed on this code path, so we must enforce it
		// here instead.
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

		var req client.ReadRequest
		if err := util.ParseProtoReader(ctx, r.Body, int(r.ContentLength), maxRemoteReadQuerySize, &req, util.RawSnappy); err != nil {
			level.Error(logger).Log("msg", "failed to parse proto", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Reject requests whose number of sub-queries exceeds the configured
		// maximum. A single ~few-KB snappy-compressed body that expands to
		// the 1 MiB decode cap can otherwise carry tens of thousands of
		// sub-queries, each fanning out to every ingester and store-gateway.
		if maxQueries > 0 && len(req.Queries) > maxQueries {
			err := fmt.Errorf("too many queries in remote read request: %d > %d (controlled by -querier.max-remote-read-queries)", len(req.Queries), maxQueries)
			level.Warn(logger).Log("msg", "rejecting remote read request", "err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Install a single, request-scoped QueryLimiter so that
		// max_fetched_chunks_per_query / max_fetched_series_per_query /
		// max_fetched_data_bytes_per_query bound the whole HTTP request
		// rather than each sub-query. The NewQueryable factory will reuse
		// this limiter instead of installing a fresh one per sub-query.
		if limits != nil {
			if userID, err := tenant.TenantID(ctx); err == nil {
				ctx = limiter.AddQueryLimiterToContext(ctx, limiter.NewQueryLimiter(
					limits.MaxFetchedSeriesPerQuery(userID),
					limits.MaxFetchedChunkBytesPerQuery(userID),
					limits.MaxChunksPerQuery(userID),
					limits.MaxFetchedDataBytesPerQuery(userID),
				))
			}
		}

		// Fetch samples for all queries using a bounded worker pool.
		resp := client.ReadResponse{
			Results: make([]*client.QueryResponse, len(req.Queries)),
		}

		jobs := make([]interface{}, len(req.Queries))
		for i := range req.Queries {
			jobs[i] = i
		}

		err := concurrency.ForEach(ctx, jobs, readConcurrency, func(ctx context.Context, jobIntf interface{}) error {
			i := jobIntf.(int)
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
