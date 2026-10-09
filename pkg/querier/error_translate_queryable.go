package querier

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/go-kit/log/level"
	"github.com/gogo/status"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// genericInternalErrorMsg is the stable, tenant-safe message returned for
// internal errors. It must not include any infrastructure identifiers
// (store-gateway addresses, object-store keys/endpoints, block ULIDs, etc.).
const genericInternalErrorMsg = "internal error, see server logs"

// redactInternalError logs the detailed error once with a correlation ID and
// returns a sanitised error carrying only a stable message plus that ID. The
// returned error is intended to be wrapped in promql.ErrStorage so Prometheus'
// API maps it to HTTP 500 while exposing no internal detail to tenants.
func redactInternalError(err error) error {
	id := ulid.MustNew(ulid.Now(), rand.Reader).String()
	level.Error(util_log.Logger).Log("msg", "query failed", "error_id", id, "err", err)
	return fmt.Errorf("%s (error_id=%s)", genericInternalErrorMsg, id)
}

// TranslateToPromqlAPIError converts error to one of promql.Errors for consumption in PromQL API.
// PromQL API only recognizes few errors, and converts everything else to HTTP status code 422.
//
// Specifically, it supports:
//
//	promql.ErrQueryCanceled, mapped to 503
//	promql.ErrQueryTimeout, mapped to 503
//	promql.ErrStorage mapped to 500
//	anything else is mapped to 422
//
// Querier code produces different kinds of errors, and we want to map them to above-mentioned HTTP status codes correctly.
//
// This function is also the sanitisation point between Cortex's internal
// query fan-out and the tenant-facing Prometheus HTTP API. Errors that are
// tenant-actionable (limit errors, PromQL engine errors, 4xx gRPC/HTTP
// statuses, context cancellation) are returned verbatim because their text is
// already safe. All other errors — which may contain internal topology or
// storage identifiers such as store-gateway instance addresses, object-store
// bucket/endpoint/key text, or block ULIDs — are logged with a correlation ID
// and replaced with a generic message before being wrapped in
// promql.ErrStorage, so the response body carries only the correlation ID.
//
// Details:
// - vendor/github.com/prometheus/prometheus/web/api/v1/api.go, respondError function only accepts *apiError types.
// - translation of error to *apiError happens in vendor/github.com/prometheus/prometheus/web/api/v1/api.go, returnAPIError method.
func TranslateToPromqlAPIError(err error) error {
	if err == nil {
		return err
	}

	switch errors.Cause(err).(type) {
	case promql.ErrStorage, promql.ErrTooManySamples, promql.ErrQueryCanceled, promql.ErrQueryTimeout:
		// Don't translate those, just in case we use them internally.
		return err
	case validation.LimitError:
		// Tenant-actionable (limits, duplicate samples, etc.) — safe to return verbatim.
		return err
	default:
		if errors.Is(err, context.Canceled) {
			return err // 422
		}

		s, ok := status.FromError(err)

		if !ok {
			s, ok = status.FromError(errors.Cause(err))
		}

		if ok {
			code := s.Code()

			// Treat these as HTTP status codes, even though they are supposed to be grpc codes.
			if code >= 400 && code < 500 {
				// Tenant-caused (bad request / not found / etc.). The upstream
				// producer is expected to have crafted a tenant-safe message —
				// return directly, will be mapped to 422.
				return err
			} else if code >= 500 && code < 599 {
				// Server-side failure. Redact: the original message may carry
				// internal topology (gRPC dial strings with IP:port, bucket
				// endpoints/keys, etc.).
				return promql.ErrStorage{Err: redactInternalError(err)}
			}
		}

		// All other errors will be returned as 500. Redact for the same reason
		// as the 5xx branch above.
		return promql.ErrStorage{Err: redactInternalError(err)}
	}
}

// ErrTranslateFn is used to translate or wrap error before returning it by functions in
// storage.SampleAndChunkQueryable interface.
// Input error may be nil.
type ErrTranslateFn func(err error) error

func NewErrorTranslateQueryable(q storage.Queryable) storage.Queryable {
	return NewErrorTranslateQueryableWithFn(q, TranslateToPromqlAPIError)
}

func NewErrorTranslateQueryableWithFn(q storage.Queryable, fn ErrTranslateFn) storage.Queryable {
	return errorTranslateQueryable{q: q, fn: fn}
}

func NewErrorTranslateSampleAndChunkQueryable(q storage.SampleAndChunkQueryable) storage.SampleAndChunkQueryable {
	return NewErrorTranslateSampleAndChunkQueryableWithFn(q, TranslateToPromqlAPIError)
}

func NewErrorTranslateSampleAndChunkQueryableWithFn(q storage.SampleAndChunkQueryable, fn ErrTranslateFn) storage.SampleAndChunkQueryable {
	return errorTranslateSampleAndChunkQueryable{q: q, fn: fn}
}

type errorTranslateQueryable struct {
	q  storage.Queryable
	fn ErrTranslateFn
}

func (e errorTranslateQueryable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	q, err := e.q.Querier(ctx, mint, maxt)
	return errorTranslateQuerier{q: q, fn: e.fn}, e.fn(err)
}

type errorTranslateSampleAndChunkQueryable struct {
	q  storage.SampleAndChunkQueryable
	fn ErrTranslateFn
}

func (e errorTranslateSampleAndChunkQueryable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	q, err := e.q.Querier(ctx, mint, maxt)
	return errorTranslateQuerier{q: q, fn: e.fn}, e.fn(err)
}

func (e errorTranslateSampleAndChunkQueryable) ChunkQuerier(ctx context.Context, mint, maxt int64) (storage.ChunkQuerier, error) {
	q, err := e.q.ChunkQuerier(ctx, mint, maxt)
	return errorTranslateChunkQuerier{q: q, fn: e.fn}, e.fn(err)
}

type errorTranslateQuerier struct {
	q  storage.Querier
	fn ErrTranslateFn
}

func (e errorTranslateQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	values, warnings, err := e.q.LabelValues(name, matchers...)
	return values, warnings, e.fn(err)
}

func (e errorTranslateQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	values, warnings, err := e.q.LabelNames(matchers...)
	return values, warnings, e.fn(err)
}

func (e errorTranslateQuerier) Close() error {
	return e.fn(e.q.Close())
}

func (e errorTranslateQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	s := e.q.Select(sortSeries, hints, matchers...)
	return errorTranslateSeriesSet{s: s, fn: e.fn}
}

type errorTranslateChunkQuerier struct {
	q  storage.ChunkQuerier
	fn ErrTranslateFn
}

func (e errorTranslateChunkQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	values, warnings, err := e.q.LabelValues(name, matchers...)
	return values, warnings, e.fn(err)
}

func (e errorTranslateChunkQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	values, warnings, err := e.q.LabelNames(matchers...)
	return values, warnings, e.fn(err)
}

func (e errorTranslateChunkQuerier) Close() error {
	return e.fn(e.q.Close())
}

func (e errorTranslateChunkQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.ChunkSeriesSet {
	s := e.q.Select(sortSeries, hints, matchers...)
	return errorTranslateChunkSeriesSet{s: s, fn: e.fn}
}

type errorTranslateSeriesSet struct {
	s  storage.SeriesSet
	fn ErrTranslateFn
}

func (e errorTranslateSeriesSet) Next() bool {
	return e.s.Next()
}

func (e errorTranslateSeriesSet) At() storage.Series {
	return e.s.At()
}

func (e errorTranslateSeriesSet) Err() error {
	return e.fn(e.s.Err())
}

func (e errorTranslateSeriesSet) Warnings() storage.Warnings {
	return e.s.Warnings()
}

type errorTranslateChunkSeriesSet struct {
	s  storage.ChunkSeriesSet
	fn ErrTranslateFn
}

func (e errorTranslateChunkSeriesSet) Next() bool {
	return e.s.Next()
}

func (e errorTranslateChunkSeriesSet) At() storage.ChunkSeries {
	return e.s.At()
}

func (e errorTranslateChunkSeriesSet) Err() error {
	return e.fn(e.s.Err())
}

func (e errorTranslateChunkSeriesSet) Warnings() storage.Warnings {
	return e.s.Warnings()
}
