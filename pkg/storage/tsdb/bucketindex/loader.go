package bucketindex

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/thanos-io/objstore"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/services"
)

const (
	// readIndexTimeout is the maximum allowed time when reading a single bucket index
	// from the storage. It's hard-coded to a reasonably high value.
	readIndexTimeout = 15 * time.Second

	// maxCachedIndexes bounds the per-tenant cache so a caller that can set an
	// arbitrary tenant ID (e.g. X-Scope-OrgID) cannot grow this map without
	// limit. When the cap is reached, the entry whose last-requested timestamp
	// is oldest is evicted to make room for the new one.
	maxCachedIndexes = 10000
)

type LoaderConfig struct {
	CheckInterval         time.Duration
	UpdateOnStaleInterval time.Duration
	UpdateOnErrorInterval time.Duration
	IdleTimeout           time.Duration
}

// Loader is responsible to lazy load bucket indexes and, once loaded for the first time,
// keep them updated in background. Loaded indexes are automatically offloaded once the
// idle timeout expires.
type Loader struct {
	services.Service

	bkt         objstore.Bucket
	logger      log.Logger
	cfg         LoaderConfig
	cfgProvider bucket.TenantConfigProvider

	indexesMx sync.RWMutex
	indexes   map[string]*cachedIndex

	// Metrics.
	loadAttempts prometheus.Counter
	loadFailures prometheus.Counter
	loadDuration prometheus.Histogram
	loaded       prometheus.GaugeFunc
}

// NewLoader makes a new Loader.
func NewLoader(cfg LoaderConfig, bucketClient objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) *Loader {
	l := &Loader{
		bkt:         bucketClient,
		logger:      logger,
		cfg:         cfg,
		cfgProvider: cfgProvider,
		indexes:     map[string]*cachedIndex{},

		loadAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cortex_bucket_index_loads_total",
			Help: "Total number of bucket index loading attempts.",
		}),
		loadFailures: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cortex_bucket_index_load_failures_total",
			Help: "Total number of bucket index loading failures.",
		}),
		loadDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "cortex_bucket_index_load_duration_seconds",
			Help:    "Duration of the a single bucket index loading operation in seconds.",
			Buckets: []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 1, 10},
		}),
	}

	l.loaded = promauto.With(reg).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_bucket_index_loaded",
		Help: "Number of bucket indexes currently loaded in-memory.",
	}, l.countLoadedIndexesMetric)

	// Apply a jitter to the sync frequency in order to increase the probability
	// of hitting the shared cache (if any).
	checkInterval := util.DurationWithJitter(cfg.CheckInterval, 0.2)
	l.Service = services.NewTimerService(checkInterval, nil, l.checkCachedIndexes, nil)

	return l
}

// GetIndex returns the bucket index for the given user. It returns the in-memory cached
// index if available, or load it from the bucket otherwise.
func (l *Loader) GetIndex(ctx context.Context, userID string) (*Index, error) {
	l.indexesMx.RLock()
	if entry := l.indexes[userID]; entry != nil {
		idx := entry.index
		err := entry.err
		l.indexesMx.RUnlock()

		// We don't check if the index is stale because it's the responsibility
		// of the background job to keep it updated.
		entry.requestedAt.Store(time.Now().Unix())
		return idx, err
	}
	l.indexesMx.RUnlock()

	startTime := time.Now()
	l.loadAttempts.Inc()
	idx, err := ReadIndex(ctx, l.bkt, userID, l.cfgProvider, l.logger)
	if err != nil {
		// Do not cache load failures that were triggered by a caller-cancelled or
		// expired context. Caching them would otherwise promote cheap
		// client-side cancellations to the aggressive UpdateOnErrorInterval
		// background refresh cadence, amplifying each cancelled request into
		// recurring object-store GETs for up to IdleTimeout.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			l.loadFailures.Inc()
			level.Warn(l.logger).Log("msg", "bucket index load aborted", "user", userID, "err", err)
			return nil, err
		}

		// Cache the error, to avoid hammering the object store in case of persistent issues
		// (eg. corrupted bucket index or not existing).
		l.cacheIndex(userID, nil, err)

		if errors.Is(err, ErrIndexNotFound) {
			level.Warn(l.logger).Log("msg", "bucket index not found", "user", userID)
		} else {
			// We don't track ErrIndexNotFound as failure because it's a legit case (eg. a tenant just
			// started to remote write and its blocks haven't uploaded to storage yet).
			l.loadFailures.Inc()
			level.Error(l.logger).Log("msg", "unable to load bucket index", "user", userID, "err", err)
		}

		return nil, err
	}

	// Cache the index.
	l.cacheIndex(userID, idx, nil)

	elapsedTime := time.Since(startTime)
	l.loadDuration.Observe(elapsedTime.Seconds())
	level.Info(l.logger).Log("msg", "loaded bucket index", "user", userID, "duration", elapsedTime)
	return idx, nil
}

func (l *Loader) cacheIndex(userID string, idx *Index, err error) {
	l.indexesMx.Lock()
	defer l.indexesMx.Unlock()

	// Bound the cache: if we are about to insert a new key and we are already
	// at the configured cap, evict the entry that was least recently requested.
	// This prevents an attacker who can set an unvalidated tenant ID header
	// from growing the map without limit.
	if _, exists := l.indexes[userID]; !exists && len(l.indexes) >= maxCachedIndexes {
		l.evictLeastRecentlyRequestedLocked()
	}

	// Not an issue if, due to concurrency, another index was already cached
	// and we overwrite it: last will win.
	l.indexes[userID] = newCachedIndex(idx, err)
}

// evictLeastRecentlyRequestedLocked removes the entry with the oldest
// requestedAt timestamp. The caller must hold l.indexesMx for writing.
func (l *Loader) evictLeastRecentlyRequestedLocked() {
	var (
		oldestUserID string
		oldestFound  bool
		oldestTS     int64
	)
	for userID, entry := range l.indexes {
		ts := entry.requestedAt.Load()
		if !oldestFound || ts < oldestTS {
			oldestUserID = userID
			oldestTS = ts
			oldestFound = true
		}
	}
	if oldestFound {
		delete(l.indexes, oldestUserID)
		level.Info(l.logger).Log("msg", "evicted bucket index", "user", oldestUserID, "reason", "cache_full")
	}
}

// checkCachedIndexes checks all cached indexes and, for each of them, does two things:
// 1. Offload indexes not requested since >= idle timeout
// 2. Update indexes which have been updated last time since >= update timeout
func (l *Loader) checkCachedIndexes(ctx context.Context) error {
	// Build a list of users for which we should update or delete the index.
	toUpdate, toDelete := l.checkCachedIndexesToUpdateAndDelete()

	// Delete unused indexes.
	for _, userID := range toDelete {
		l.deleteCachedIndex(userID)
	}

	// Update actively used indexes.
	for _, userID := range toUpdate {
		l.updateCachedIndex(ctx, userID)
	}

	// Never return error, otherwise the service terminates.
	return nil
}

func (l *Loader) checkCachedIndexesToUpdateAndDelete() (toUpdate, toDelete []string) {
	now := time.Now()

	l.indexesMx.RLock()
	defer l.indexesMx.RUnlock()

	for userID, entry := range l.indexes {
		// Given ErrIndexNotFound is a legit case and assuming UpdateOnErrorInterval is lower than
		// UpdateOnStaleInterval, we don't consider ErrIndexNotFound as an error with regards to the
		// refresh interval and so it will updated once stale.
		isError := entry.err != nil && !errors.Is(entry.err, ErrIndexNotFound)

		switch {
		case now.Sub(entry.getRequestedAt()) >= l.cfg.IdleTimeout:
			toDelete = append(toDelete, userID)
		case isError && now.Sub(entry.getUpdatedAt()) >= l.cfg.UpdateOnErrorInterval:
			toUpdate = append(toUpdate, userID)
		case !isError && now.Sub(entry.getUpdatedAt()) >= l.cfg.UpdateOnStaleInterval:
			toUpdate = append(toUpdate, userID)
		}
	}

	return
}

func (l *Loader) updateCachedIndex(ctx context.Context, userID string) {
	readCtx, cancel := context.WithTimeout(ctx, readIndexTimeout)
	defer cancel()

	l.loadAttempts.Inc()
	startTime := time.Now()
	idx, err := ReadIndex(readCtx, l.bkt, userID, l.cfgProvider, l.logger)
	if err != nil && !errors.Is(err, ErrIndexNotFound) {
		l.loadFailures.Inc()
		level.Warn(l.logger).Log("msg", "unable to update bucket index", "user", userID, "err", err)
		return
	}

	l.loadDuration.Observe(time.Since(startTime).Seconds())

	// We cache it either it was successfully refreshed or wasn't found. An use case for caching the ErrIndexNotFound
	// is when a tenant has rules configured but hasn't started remote writing yet. Rules will be evaluated and
	// bucket index loaded by the ruler.
	l.indexesMx.Lock()
	l.indexes[userID].index = idx
	l.indexes[userID].err = err
	l.indexes[userID].setUpdatedAt(startTime)
	l.indexesMx.Unlock()
}

func (l *Loader) deleteCachedIndex(userID string) {
	l.indexesMx.Lock()
	delete(l.indexes, userID)
	l.indexesMx.Unlock()

	level.Info(l.logger).Log("msg", "unloaded bucket index", "user", userID, "reason", "idle")
}

func (l *Loader) countLoadedIndexesMetric() float64 {
	l.indexesMx.RLock()
	defer l.indexesMx.RUnlock()

	count := 0
	for _, idx := range l.indexes {
		if idx.index != nil {
			count++
		}
	}
	return float64(count)
}

type cachedIndex struct {
	// We cache either the index or the error occurred while fetching it. They're
	// mutually exclusive.
	index *Index
	err   error

	// Unix timestamp (seconds) of when the index has been updated from the storage the last time.
	updatedAt atomic.Int64

	// Unix timestamp (seconds) of when the index has been requested the last time.
	requestedAt atomic.Int64
}

func newCachedIndex(idx *Index, err error) *cachedIndex {
	entry := &cachedIndex{
		index: idx,
		err:   err,
	}

	now := time.Now()
	entry.setUpdatedAt(now)
	entry.setRequestedAt(now)

	return entry
}

func (i *cachedIndex) setUpdatedAt(ts time.Time) {
	i.updatedAt.Store(ts.Unix())
}

func (i *cachedIndex) getUpdatedAt() time.Time {
	return time.Unix(i.updatedAt.Load(), 0)
}

func (i *cachedIndex) setRequestedAt(ts time.Time) {
	i.requestedAt.Store(ts.Unix())
}

func (i *cachedIndex) getRequestedAt() time.Time {
	return time.Unix(i.requestedAt.Load(), 0)
}
