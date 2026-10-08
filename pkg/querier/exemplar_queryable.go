// SPDX-License-Identifier: AGPL-3.0-only
//
// This wrapper gives the exemplar read path the same guard rails that the
// sample path gets inside NewQueryable in querier.go: a per-query limiter,
// time-range validation (max_query_into_future / max_query_lookback), the
// max_query_length check, and a cap on the number of selector sets that
// are fanned out to every ingester.

package querier

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/limiter"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// limitedExemplarQueryable wraps an ExemplarQueryable so each ExemplarQuerier
// returned has an attached per-query QueryLimiter and enforces the time-range
// and selector-count limits before dispatching to the distributor.
type limitedExemplarQueryable struct {
	next               storage.ExemplarQueryable
	limits             *validation.Overrides
	maxQueryIntoFuture time.Duration
}

func newLimitedExemplarQueryable(next storage.ExemplarQueryable, limits *validation.Overrides, maxQueryIntoFuture time.Duration) storage.ExemplarQueryable {
	return &limitedExemplarQueryable{
		next:               next,
		limits:             limits,
		maxQueryIntoFuture: maxQueryIntoFuture,
	}
}

func (d *limitedExemplarQueryable) ExemplarQuerier(ctx context.Context) (storage.ExemplarQuerier, error) {
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		return nil, err
	}

	ctx = limiter.AddQueryLimiterToContext(ctx, limiter.NewQueryLimiter(
		d.limits.MaxFetchedSeriesPerQuery(userID),
		d.limits.MaxFetchedChunkBytesPerQuery(userID),
		d.limits.MaxChunksPerQuery(userID),
		d.limits.MaxFetchedDataBytesPerQuery(userID),
	))

	next, err := d.next.ExemplarQuerier(ctx)
	if err != nil {
		return nil, err
	}

	return &limitedExemplarQuerier{
		next:               next,
		ctx:                ctx,
		userID:             userID,
		limits:             d.limits,
		maxQueryIntoFuture: d.maxQueryIntoFuture,
	}, nil
}

type limitedExemplarQuerier struct {
	next               storage.ExemplarQuerier
	ctx                context.Context
	userID             string
	limits             *validation.Overrides
	maxQueryIntoFuture time.Duration
}

// Select enforces the same per-query limits as the sample path and, in
// addition, bounds the number of selector sets we are willing to decode and
// fan out to every ingester for an exemplar query.
func (q *limitedExemplarQuerier) Select(start, end int64, matchers ...[]*labels.Matcher) ([]exemplar.QueryResult, error) {
	// Clamp / reject the time range (max_query_into_future, max_query_lookback).
	start, end, err := validateQueryTimeRange(q.ctx, q.userID, start, end, q.limits, q.maxQueryIntoFuture)
	if err == errEmptyTimeRange {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// max_query_length.
	if maxQueryLength := q.limits.MaxQueryLength(q.userID); maxQueryLength > 0 {
		if length := model.Time(end).Sub(model.Time(start)); length > maxQueryLength {
			return nil, validation.LimitError(fmt.Sprintf(validation.ErrQueryTooLong, length, maxQueryLength))
		}
	}

	// Cap the number of selector sets. Each selector set is translated into one
	// LabelMatchers group and fanned out to every ingester, so an unbounded N
	// is directly amplified by the number of ingesters in the ring.
	if max := q.limits.MaxExemplarsPerQuery(q.userID); max > 0 && len(matchers) > max {
		return nil, validation.LimitError(fmt.Sprintf("too many selectors in exemplar query: %d (limit: %d)", len(matchers), max))
	}

	return q.next.Select(start, end, matchers...)
}
