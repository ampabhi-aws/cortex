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

	// heartbeatWG tracks all heartbeat goroutines started by Plan so the
	// caller can drain them before the compaction run ends.
	heartbeatWG sync.WaitGroup
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

	// Fall back to the planner's construction-time context if the caller did
	// not supply one (e.g. older tests). In production Thanos' BucketCompactor
	// always passes its per-iteration workCtx.
	if ctx == nil {
		ctx = p.ctx
	}

	for _, b := range metasByMinTime {
		blockID := b.ULID.String()
		if _, excluded := noCompactMarked[b.ULID]; excluded {
			continue
		}

		if b.MinTime < rangeStart || b.MaxTime > rangeEnd {
			return nil, fmt.Errorf("block %s with time range %d:%d is outside the largest expected range %d:%d", blockID, b.MinTime, b.MaxTime, rangeStart, rangeEnd)
		}

		blockVisitMarker, err := ReadBlockVisitMarker(ctx, p.bkt, p.logger, blockID, p.blockVisitMarkerReadFailed)
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

	// Scope the heartbeat to the compaction group it protects. We derive a
	// child context from the Plan ctx (which is Thanos' per-iteration workCtx
	// passed through Group.Compact), so when the compaction for this group
	// returns and the work loop iteration completes, the heartbeat exits.
	// Track the goroutine so Close() can drain all heartbeats before the
	// per-tenant compaction run ends.
	p.heartbeatWG.Add(1)
	go func() {
		defer p.heartbeatWG.Done()
		markBlocksVisitedHeartBeat(ctx, p.bkt, p.logger, resultMetas, p.ringLifecyclerID, p.blockVisitMarkerFileUpdateInterval, p.blockVisitMarkerWriteFailed)
	}()

	return resultMetas, nil
}

// Close blocks until every heartbeat goroutine previously started by Plan
// has returned. It must be called by the owner of the planner (typically
// Compactor.compactUser) after the per-tenant context has been cancelled,
// so that no leaked heartbeat survives the compaction run.
func (p *ShuffleShardingPlanner) Close() {
	p.heartbeatWG.Wait()
}
