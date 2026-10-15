package compactor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/oklog/ulid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/thanos/pkg/block/metadata"
)

type ShuffleShardingPlanner struct {
	ctx                                context.Context
	bkt                                objstore.InstrumentedBucket
	logger                             log.Logger
	ranges                             []int64
	noCompBlocksFunc                   func() map[ulid.ULID]*metadata.NoCompactMark
	ringLifecyclerID                   string
	blockVisitMarkerTimeout            time.Duration
	blockVisitMarkerFileUpdateInterval time.Duration
	blockVisitMarkerReadFailed         prometheus.Counter
	blockVisitMarkerWriteFailed        prometheus.Counter
	blockVisitMarkerHeartbeats         prometheus.Gauge

	// heartbeatsMtx protects heartbeatCancels and heartbeatsWg access on Close.
	heartbeatsMtx     sync.Mutex
	heartbeatCancels  []context.CancelFunc
	heartbeatsWg      sync.WaitGroup
	heartbeatsStopped bool
}

func NewShuffleShardingPlanner(
	ctx context.Context,
	bkt objstore.InstrumentedBucket,
	logger log.Logger,
	ranges []int64,
	noCompBlocksFunc func() map[ulid.ULID]*metadata.NoCompactMark,
	ringLifecyclerID string,
	blockVisitMarkerTimeout time.Duration,
	blockVisitMarkerFileUpdateInterval time.Duration,
	blockVisitMarkerReadFailed prometheus.Counter,
	blockVisitMarkerWriteFailed prometheus.Counter,
) *ShuffleShardingPlanner {
	return NewShuffleShardingPlannerWithMetrics(ctx, bkt, logger, ranges, noCompBlocksFunc, ringLifecyclerID, blockVisitMarkerTimeout, blockVisitMarkerFileUpdateInterval, blockVisitMarkerReadFailed, blockVisitMarkerWriteFailed, nil)
}

// NewShuffleShardingPlannerWithMetrics is like NewShuffleShardingPlanner but also wires in
// an optional gauge that tracks the number of live block-visit-marker heartbeat goroutines
// so leaks are observable.
func NewShuffleShardingPlannerWithMetrics(
	ctx context.Context,
	bkt objstore.InstrumentedBucket,
	logger log.Logger,
	ranges []int64,
	noCompBlocksFunc func() map[ulid.ULID]*metadata.NoCompactMark,
	ringLifecyclerID string,
	blockVisitMarkerTimeout time.Duration,
	blockVisitMarkerFileUpdateInterval time.Duration,
	blockVisitMarkerReadFailed prometheus.Counter,
	blockVisitMarkerWriteFailed prometheus.Counter,
	blockVisitMarkerHeartbeats prometheus.Gauge,
) *ShuffleShardingPlanner {
	return &ShuffleShardingPlanner{
		ctx:                                ctx,
		bkt:                                bkt,
		logger:                             logger,
		ranges:                             ranges,
		noCompBlocksFunc:                   noCompBlocksFunc,
		ringLifecyclerID:                   ringLifecyclerID,
		blockVisitMarkerTimeout:            blockVisitMarkerTimeout,
		blockVisitMarkerFileUpdateInterval: blockVisitMarkerFileUpdateInterval,
		blockVisitMarkerReadFailed:         blockVisitMarkerReadFailed,
		blockVisitMarkerWriteFailed:        blockVisitMarkerWriteFailed,
		blockVisitMarkerHeartbeats:         blockVisitMarkerHeartbeats,
	}
}

func (p *ShuffleShardingPlanner) Plan(ctx context.Context, metasByMinTime []*metadata.Meta) ([]*metadata.Meta, error) {
	// Ensure all blocks fits within the largest range. This is a double check
	// to ensure there's no bug in the previous blocks grouping, given this Plan()
	// is just a pass-through.
	// Modifed from https://github.com/cortexproject/cortex/pull/2616/files#diff-e3051fc530c48bb276ba958dd8fadc684e546bd7964e6bc75cef9a86ef8df344R28-R63
	largestRange := p.ranges[len(p.ranges)-1]
	rangeStart := getRangeStart(metasByMinTime[0], largestRange)
	rangeEnd := rangeStart + largestRange
	noCompactMarked := p.noCompBlocksFunc()
	resultMetas := make([]*metadata.Meta, 0, len(metasByMinTime))

	for _, b := range metasByMinTime {
		blockID := b.ULID.String()
		if _, excluded := noCompactMarked[b.ULID]; excluded {
			continue
		}

		if b.MinTime < rangeStart || b.MaxTime > rangeEnd {
			return nil, fmt.Errorf("block %s with time range %d:%d is outside the largest expected range %d:%d", blockID, b.MinTime, b.MaxTime, rangeStart, rangeEnd)
		}

		blockVisitMarker, err := ReadBlockVisitMarker(p.ctx, p.bkt, p.logger, blockID, p.blockVisitMarkerReadFailed)
		if err != nil {
			// shuffle_sharding_grouper should put visit marker file for blocks ready for
			// compaction. So error should be returned if visit marker file does not exist.
			return nil, fmt.Errorf("unable to get visit marker file for block %s: %s", blockID, err.Error())
		}
		if !blockVisitMarker.isVisitedByCompactor(p.blockVisitMarkerTimeout, p.ringLifecyclerID) {
			return nil, fmt.Errorf("block %s is not visited by current compactor %s", blockID, p.ringLifecyclerID)
		}

		resultMetas = append(resultMetas, b)
	}

	if len(resultMetas) < 2 {
		return nil, nil
	}

	// Scope the heartbeat to this group so it stops as soon as the group's compaction
	// finishes. We derive from the per-call ctx (per-Compact-iteration) when available so
	// that cancellation of the Compact pass terminates heartbeats for all groups planned
	// in that pass; we also keep a cancel handle so Close() can tear down any heartbeat
	// that is still running. The underlying heartbeat loop additionally self-terminates
	// when every block it is tracking has been removed from the bucket.
	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = p.ctx
	}
	hbCtx, cancel := context.WithCancel(parentCtx)

	p.heartbeatsMtx.Lock()
	if p.heartbeatsStopped {
		// Planner has been closed; do not launch new heartbeats.
		p.heartbeatsMtx.Unlock()
		cancel()
		return resultMetas, nil
	}
	p.heartbeatCancels = append(p.heartbeatCancels, cancel)
	p.heartbeatsWg.Add(1)
	p.heartbeatsMtx.Unlock()

	go markBlocksVisitedHeartBeat(hbCtx, p.bkt, p.logger, resultMetas, p.ringLifecyclerID, p.blockVisitMarkerFileUpdateInterval, p.blockVisitMarkerWriteFailed, p.blockVisitMarkerHeartbeats, &p.heartbeatsWg)

	return resultMetas, nil
}

// Close cancels every heartbeat goroutine the planner has started and waits for them to
// exit. It is safe to call multiple times. Call this when the planner is no longer needed
// (e.g. after BucketCompactor.Compact returns) so that heartbeats do not outlive their
// enclosing scope even if their per-group contexts are still live.
func (p *ShuffleShardingPlanner) Close() {
	p.heartbeatsMtx.Lock()
	if p.heartbeatsStopped {
		p.heartbeatsMtx.Unlock()
		return
	}
	p.heartbeatsStopped = true
	cancels := p.heartbeatCancels
	p.heartbeatCancels = nil
	p.heartbeatsMtx.Unlock()

	for _, c := range cancels {
		c()
	}
	p.heartbeatsWg.Wait()
}
