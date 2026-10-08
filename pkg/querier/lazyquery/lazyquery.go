package lazyquery

import (
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

// defaultMaxConcurrentSelects is used when NewLazyQuerier is called with a
// non-positive maxConcurrentSelects value. It bounds the number of goroutines
// started by a single LazyQuerier so a pathological PromQL expression with
// many VectorSelectors cannot amplify into an unbounded number of concurrent
// distributed fan-outs.
const defaultMaxConcurrentSelects = 16

// LazyQuerier is a lazy-loaded adapter for a storage.Querier
type LazyQuerier struct {
	next storage.Querier
	// sem is a shared, per-request semaphore bounding the number of
	// in-flight Select goroutines spawned by this Querier. It is sized once
	// at construction time via NewLazyQuerier.
	sem chan struct{}
}

// NewLazyQuerier wraps a storage.Querier, does the Select in the background.
// maxConcurrentSelects bounds the number of concurrent in-flight Selects for
// this Querier instance. A value <= 0 falls back to a safe default so callers
// that do not know about the bound still get backpressure (CWE-770).
// Return value cannot be used from more than one goroutine simultaneously.
func NewLazyQuerier(next storage.Querier, maxConcurrentSelects int) storage.Querier {
	if maxConcurrentSelects <= 0 {
		maxConcurrentSelects = defaultMaxConcurrentSelects
	}
	return LazyQuerier{
		next: next,
		sem:  make(chan struct{}, maxConcurrentSelects),
	}
}

// Select implements Storage.Querier
func (l LazyQuerier) Select(selectSorted bool, params *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	// make sure there is space in the buffer, to unblock the goroutine and let it die even if nobody is
	// waiting for the result yet (or anymore).
	future := make(chan storage.SeriesSet, 1)
	go func() {
		// Bound in-flight Selects for this Querier. This provides
		// backpressure against expressions with a very large number of
		// VectorSelectors (one Select per selector), which would otherwise
		// start K concurrent distributed fan-outs and exhaust goroutines,
		// gRPC streams, and memory on the querier and its backends.
		l.sem <- struct{}{}
		defer func() { <-l.sem }()
		future <- l.next.Select(selectSorted, params, matchers...)
	}()

	return &lazySeriesSet{
		future: future,
	}
}

// LabelValues implements Storage.Querier
func (l LazyQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return l.next.LabelValues(name, matchers...)
}

// LabelNames implements Storage.Querier
func (l LazyQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return l.next.LabelNames(matchers...)
}

// Close implements Storage.Querier
func (l LazyQuerier) Close() error {
	return l.next.Close()
}

type lazySeriesSet struct {
	next   storage.SeriesSet
	future chan storage.SeriesSet
}

// Next implements storage.SeriesSet.  NB not thread safe!
func (s *lazySeriesSet) Next() bool {
	if s.next == nil {
		s.next = <-s.future
	}
	return s.next.Next()
}

// At implements storage.SeriesSet.
func (s *lazySeriesSet) At() storage.Series {
	if s.next == nil {
		s.next = <-s.future
	}
	return s.next.At()
}

// Err implements storage.SeriesSet.
func (s *lazySeriesSet) Err() error {
	if s.next == nil {
		s.next = <-s.future
	}
	return s.next.Err()
}

// Warnings implements storage.SeriesSet.
func (s *lazySeriesSet) Warnings() storage.Warnings {
	return nil
}
