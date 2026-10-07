package querier

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/scrape"
	"github.com/prometheus/prometheus/storage"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/ingester/client"
	"github.com/cortexproject/cortex/pkg/prom1/storage/metric"
	"github.com/cortexproject/cortex/pkg/querier/series"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/chunkcompat"
	"github.com/cortexproject/cortex/pkg/util/math"
	"github.com/cortexproject/cortex/pkg/util/spanlogger"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// Distributor is the read interface to the distributor, made an interface here
// to reduce package coupling.
type Distributor interface {
	Query(ctx context.Context, from, to model.Time, matchers ...*labels.Matcher) (model.Matrix, error)
	QueryStream(ctx context.Context, from, to model.Time, matchers ...*labels.Matcher) (*client.QueryStreamResponse, error)
	QueryExemplars(ctx context.Context, from, to model.Time, matchers ...[]*labels.Matcher) (*client.ExemplarQueryResponse, error)
	LabelValuesForLabelName(ctx context.Context, from, to model.Time, label model.LabelName, matchers ...*labels.Matcher) ([]string, error)
	LabelValuesForLabelNameStream(ctx context.Context, from, to model.Time, label model.LabelName, matchers ...*labels.Matcher) ([]string, error)
	LabelNames(context.Context, model.Time, model.Time) ([]string, error)
	LabelNamesStream(context.Context, model.Time, model.Time) ([]string, error)
	MetricsForLabelMatchers(ctx context.Context, from, through model.Time, matchers ...*labels.Matcher) ([]metric.Metric, error)
	MetricsForLabelMatchersStream(ctx context.Context, from, through model.Time, matchers ...*labels.Matcher) ([]metric.Metric, error)
	MetricsMetadata(ctx context.Context) ([]scrape.MetricMetadata, error)
}

func newDistributorQueryable(distributor Distributor, streaming bool, streamingMetdata bool, iteratorFn chunkIteratorFunc, queryIngestersWithin time.Duration) QueryableWithFilter {
	return distributorQueryable{
		distributor:          distributor,
		streaming:            streaming,
		streamingMetdata:     streamingMetdata,
		iteratorFn:           iteratorFn,
		queryIngestersWithin: queryIngestersWithin,
	}
}

type distributorQueryable struct {
	distributor          Distributor
	streaming            bool
	streamingMetdata     bool
	iteratorFn           chunkIteratorFunc
	queryIngestersWithin time.Duration
}

func (d distributorQueryable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	return &distributorQuerier{
		distributor:          d.distributor,
		ctx:                  ctx,
		mint:                 mint,
		maxt:                 maxt,
		streaming:            d.streaming,
		streamingMetadata:    d.streamingMetdata,
		chunkIterFn:          d.iteratorFn,
		queryIngestersWithin: d.queryIngestersWithin,
	}, nil
}

func (d distributorQueryable) UseQueryable(now time.Time, _, queryMaxT int64) bool {
	// Include ingester only if maxt is within QueryIngestersWithin w.r.t. current time.
	return d.queryIngestersWithin == 0 || queryMaxT >= util.TimeToMillis(now.Add(-d.queryIngestersWithin))
}

type distributorQuerier struct {
	distributor          Distributor
	ctx                  context.Context
	mint, maxt           int64
	streaming            bool
	streamingMetadata    bool
	chunkIterFn          chunkIteratorFunc
	queryIngestersWithin time.Duration
}

// Select implements storage.Querier interface.
// The bool passed is ignored because the series is always sorted.
func (q *distributorQuerier) Select(sortSeries bool, sp *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	log, ctx := spanlogger.New(q.ctx, "distributorQuerier.Select")
	defer log.Span.Finish()

	minT, maxT := q.mint, q.maxt
	if sp != nil {
		minT, maxT = sp.Start, sp.End
	}

	// If the querier receives a 'series' query, it means only metadata is needed.
	// For this specific case we shouldn't apply the queryIngestersWithin
	// time range manipulation, otherwise we'll end up returning no series at all for
	// older time ranges (while in Cortex we do ignore the start/end and always return
	// series in ingesters).
	// Also, in the recent versions of Prometheus, we pass in the hint but with Func set to "series".
	// See: https://github.com/prometheus/prometheus/pull/8050
	if sp != nil && sp.Func == "series" {
		var (
			ms  []metric.Metric
			err error
		)

		if q.streamingMetadata {
			ms, err = q.distributor.MetricsForLabelMatchersStream(ctx, model.Time(q.mint), model.Time(q.maxt), matchers...)
		} else {
			ms, err = q.distributor.MetricsForLabelMatchers(ctx, model.Time(q.mint), model.Time(q.maxt), matchers...)
		}

		if err != nil {
			return storage.ErrSeriesSet(err)
		}
		return series.MetricsToSeriesSet(sortSeries, ms)
	}

	// If queryIngestersWithin is enabled, we do manipulate the query mint to query samples up until
	// now - queryIngestersWithin, because older time ranges are covered by the storage. This
	// optimization is particularly important for the blocks storage where the blocks retention in the
	// ingesters could be way higher than queryIngestersWithin.
	if q.queryIngestersWithin > 0 {
		now := time.Now()
		origMinT := minT
		minT = math.Max64(minT, util.TimeToMillis(now.Add(-q.queryIngestersWithin)))

		if origMinT != minT {
			level.Debug(log).Log("msg", "the min time of the query to ingesters has been manipulated", "original", origMinT, "updated", minT)
		}

		if minT > maxT {
			level.Debug(log).Log("msg", "empty query time range after min time manipulation")
			return storage.EmptySeriesSet()
		}
	}

	if q.streaming {
		return q.streamingSelect(ctx, sortSeries, minT, maxT, matchers)
	}

	matrix, err := q.distributor.Query(ctx, model.Time(minT), model.Time(maxT), matchers...)
	if err != nil {
		return storage.ErrSeriesSet(err)
	}

	// Using MatrixToSeriesSet (and in turn NewConcreteSeriesSet), sorts the series.
	return series.MatrixToSeriesSet(sortSeries, matrix)
}

func (q *distributorQuerier) streamingSelect(ctx context.Context, sortSeries bool, minT, maxT int64, matchers []*labels.Matcher) storage.SeriesSet {
	results, err := q.distributor.QueryStream(ctx, model.Time(minT), model.Time(maxT), matchers...)
	if err != nil {
		return storage.ErrSeriesSet(err)
	}

	// we should sort the series if we need to merge them even if sortSeries is not required by the querier
	sortSeries = sortSeries || (len(results.Timeseries) > 0 && len(results.Chunkseries) > 0)
	sets := []storage.SeriesSet(nil)
	if len(results.Timeseries) > 0 {
		sets = append(sets, newTimeSeriesSeriesSet(sortSeries, results.Timeseries))
	}

	serieses := make([]storage.Series, 0, len(results.Chunkseries))
	for _, result := range results.Chunkseries {
		// Sometimes the ingester can send series that have no data.
		if len(result.Chunks) == 0 {
			continue
		}

		ls := cortexpb.FromLabelAdaptersToLabels(result.Labels)

		chunks, err := chunkcompat.FromChunks(ls, result.Chunks)
		if err != nil {
			return storage.ErrSeriesSet(err)
		}

		serieses = append(serieses, &chunkSeries{
			labels:            ls,
			chunks:            chunks,
			chunkIteratorFunc: q.chunkIterFn,
			mint:              minT,
			maxt:              maxT,
		})
	}

	if len(serieses) > 0 {
		sets = append(sets, series.NewConcreteSeriesSet(sortSeries || len(sets) > 0, serieses))
	}

	if len(sets) == 0 {
		return storage.EmptySeriesSet()
	}
	if len(sets) == 1 {
		return sets[0]
	}
	// Sets need to be sorted. Both series.NewConcreteSeriesSet and newTimeSeriesSeriesSet take care of that.
	return storage.NewMergeSeriesSet(sets, storage.ChainedSeriesMerge)
}

func (q *distributorQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	var (
		lvs []string
		err error
	)

	if q.streamingMetadata {
		lvs, err = q.distributor.LabelValuesForLabelNameStream(q.ctx, model.Time(q.mint), model.Time(q.maxt), model.LabelName(name), matchers...)
	} else {
		lvs, err = q.distributor.LabelValuesForLabelName(q.ctx, model.Time(q.mint), model.Time(q.maxt), model.LabelName(name), matchers...)
	}

	return lvs, nil, err
}

func (q *distributorQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	if len(matchers) > 0 {
		return q.labelNamesWithMatchers(matchers...)
	}

	log, ctx := spanlogger.New(q.ctx, "distributorQuerier.LabelNames")
	defer log.Span.Finish()

	var (
		ln  []string
		err error
	)

	if q.streamingMetadata {
		ln, err = q.distributor.LabelNamesStream(ctx, model.Time(q.mint), model.Time(q.maxt))
	} else {
		ln, err = q.distributor.LabelNames(ctx, model.Time(q.mint), model.Time(q.maxt))
	}

	return ln, nil, err
}

// labelNamesWithMatchers performs the LabelNames call by calling ingester's MetricsForLabelMatchers method
func (q *distributorQuerier) labelNamesWithMatchers(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	log, ctx := spanlogger.New(q.ctx, "distributorQuerier.labelNamesWithMatchers")
	defer log.Span.Finish()

	var (
		ms  []metric.Metric
		err error
	)

	if q.streamingMetadata {
		ms, err = q.distributor.MetricsForLabelMatchersStream(ctx, model.Time(q.mint), model.Time(q.maxt), matchers...)
	} else {
		ms, err = q.distributor.MetricsForLabelMatchers(ctx, model.Time(q.mint), model.Time(q.maxt), matchers...)
	}

	if err != nil {
		return nil, nil, err
	}
	namesMap := make(map[string]struct{})

	for _, m := range ms {
		for name := range m.Metric {
			namesMap[string(name)] = struct{}{}
		}
	}

	names := make([]string, 0, len(namesMap))
	for name := range namesMap {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, nil, nil
}

func (q *distributorQuerier) Close() error {
	return nil
}

type distributorExemplarQueryable struct {
	distributor Distributor
	cfg         Config
	limits      *validation.Overrides
}

func newDistributorExemplarQueryable(d Distributor, cfg Config, limits *validation.Overrides) storage.ExemplarQueryable {
	return &distributorExemplarQueryable{
		distributor: d,
		cfg:         cfg,
		limits:      limits,
	}
}

func (d distributorExemplarQueryable) ExemplarQuerier(ctx context.Context) (storage.ExemplarQuerier, error) {
	return &distributorExemplarQuerier{
		distributor: d.distributor,
		cfg:         d.cfg,
		limits:      d.limits,
		ctx:         ctx,
	}, nil
}

type distributorExemplarQuerier struct {
	distributor Distributor
	cfg         Config
	limits      *validation.Overrides
	ctx         context.Context
}

// Select querys for exemplars, prometheus' storage.ExemplarQuerier's Select function takes the time range as two int64 values.
func (q *distributorExemplarQuerier) Select(start, end int64, matchers ...[]*labels.Matcher) ([]exemplar.QueryResult, error) {
	// Fail fast if the request is already cancelled: the ingester-side
	// exemplar Select loop holds a read lock and never checks the context,
	// so there is no point in dispatching work that we know we cannot stop.
	if err := q.ctx.Err(); err != nil {
		return nil, err
	}

	// Apply the same per-tenant limits that other read paths get through
	// NewQueryable / querier.Select. The exemplar queryable is created
	// separately and does not go through the tripperware limits chain,
	// so it needs its own validation to avoid an unbounded, uncancellable
	// fan-out to every ingester.
	if q.limits != nil {
		userID, err := tenant.TenantID(q.ctx)
		if err != nil {
			return nil, err
		}

		// Cap the number of label-matcher sets a single exemplar query may
		// carry. Prometheus' CircularExemplarStorage.Select walks the per
		// tenant exemplar index once per entry and evaluates every matcher
		// set under a read lock without any ctx.Err() check, so the cost
		// grows as O(exemplar_index * matcher_sets). Reject obviously
		// abusive requests before dispatching them to every ingester.
		if maxSets := q.limits.MaxExemplarMatcherSetsPerQuery(userID); maxSets > 0 && len(matchers) > maxSets {
			return nil, validation.LimitError(fmt.Sprintf("the query exceeds the maximum number of label-matcher sets allowed per exemplar query (limit: %d actual: %d)", maxSets, len(matchers)))
		}

		// Clamp the time range to [-max_query_lookback, now+max_query_into_future]
		// in the same way as the sample read path, and enforce max_query_length.
		startMs, endMs, err := validateQueryTimeRange(q.ctx, userID, start, end, q.limits, q.cfg.MaxQueryIntoFuture)
		if err == errEmptyTimeRange {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		if maxQueryLength := q.limits.MaxQueryLength(userID); maxQueryLength > 0 && time.Duration(endMs-startMs)*time.Millisecond > maxQueryLength {
			return nil, validation.LimitError(fmt.Sprintf(validation.ErrQueryTooLong, time.Duration(endMs-startMs)*time.Millisecond, maxQueryLength))
		}
		start, end = startMs, endMs
	}

	allResults, err := q.distributor.QueryExemplars(q.ctx, model.Time(start), model.Time(end), matchers...)

	if err != nil {
		return nil, err
	}

	var e exemplar.QueryResult
	ret := make([]exemplar.QueryResult, len(allResults.Timeseries))
	for i, ts := range allResults.Timeseries {
		e.SeriesLabels = cortexpb.FromLabelAdaptersToLabels(ts.Labels)
		e.Exemplars = cortexpb.FromExemplarProtosToExemplars(ts.Exemplars)
		ret[i] = e
	}
	return ret, nil
}
