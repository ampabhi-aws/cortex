package compactor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/thanos/pkg/block/metadata"

	"github.com/cortexproject/cortex/pkg/util/runutil"
)

const (
	// BlockVisitMarkerFile is the known json filename for representing the most recent compactor visit.
	BlockVisitMarkerFile = "visit-mark.json"
	// VisitMarkerVersion1 is the current supported version of visit-mark file.
	VisitMarkerVersion1 = 1
)

var (
	ErrorBlockVisitMarkerNotFound  = errors.New("block visit marker not found")
	ErrorUnmarshalBlockVisitMarker = errors.New("unmarshal block visit marker JSON")
)

type BlockVisitMarker struct {
	CompactorID string `json:"compactorID"`
	// VisitTime is a unix timestamp of when the block was visited (mark updated).
	VisitTime int64 `json:"visitTime"`
	// Version of the file.
	Version int `json:"version"`
}

func (b *BlockVisitMarker) isVisited(blockVisitMarkerTimeout time.Duration) bool {
	return time.Now().Before(time.Unix(b.VisitTime, 0).Add(blockVisitMarkerTimeout))
}

func (b *BlockVisitMarker) isVisitedByCompactor(blockVisitMarkerTimeout time.Duration, compactorID string) bool {
	return b.CompactorID == compactorID && time.Now().Before(time.Unix(b.VisitTime, 0).Add(blockVisitMarkerTimeout))
}

func ReadBlockVisitMarker(ctx context.Context, bkt objstore.InstrumentedBucketReader, logger log.Logger, blockID string, blockVisitMarkerReadFailed prometheus.Counter) (*BlockVisitMarker, error) {
	visitMarkerFile := path.Join(blockID, BlockVisitMarkerFile)
	visitMarkerFileReader, err := bkt.ReaderWithExpectedErrs(bkt.IsObjNotFoundErr).Get(ctx, visitMarkerFile)
	if err != nil {
		if bkt.IsObjNotFoundErr(err) {
			return nil, errors.Wrapf(ErrorBlockVisitMarkerNotFound, "block visit marker file: %s", visitMarkerFile)
		}
		blockVisitMarkerReadFailed.Inc()
		return nil, errors.Wrapf(err, "get block visit marker file: %s", visitMarkerFile)
	}
	defer runutil.CloseWithLogOnErr(logger, visitMarkerFileReader, "close block visit marker reader")
	b, err := io.ReadAll(visitMarkerFileReader)
	if err != nil {
		blockVisitMarkerReadFailed.Inc()
		return nil, errors.Wrapf(err, "read block visit marker file: %s", visitMarkerFile)
	}
	blockVisitMarker := BlockVisitMarker{}
	if err = json.Unmarshal(b, &blockVisitMarker); err != nil {
		blockVisitMarkerReadFailed.Inc()
		return nil, errors.Wrapf(ErrorUnmarshalBlockVisitMarker, "block visit marker file: %s, error: %v", visitMarkerFile, err.Error())
	}
	if blockVisitMarker.Version != VisitMarkerVersion1 {
		return nil, errors.Errorf("unexpected block visit mark file version %d, expected %d", blockVisitMarker.Version, VisitMarkerVersion1)
	}
	return &blockVisitMarker, nil
}

func UpdateBlockVisitMarker(ctx context.Context, bkt objstore.Bucket, blockID string, reader io.Reader, blockVisitMarkerWriteFailed prometheus.Counter) error {
	blockVisitMarkerFilePath := path.Join(blockID, BlockVisitMarkerFile)
	if err := bkt.Upload(ctx, blockVisitMarkerFilePath, reader); err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return err
	}
	return nil
}

func markBlocksVisited(
	ctx context.Context,
	bkt objstore.Bucket,
	logger log.Logger,
	blocks []*metadata.Meta,
	marker BlockVisitMarker,
	blockVisitMarkerWriteFailed prometheus.Counter,
) {
	visitMarkerFileContent, err := json.Marshal(marker)
	if err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return
	}
	reader := bytes.NewReader(visitMarkerFileContent)
	for _, block := range blocks {
		blockID := block.ULID.String()
		if err := UpdateBlockVisitMarker(ctx, bkt, blockID, reader, blockVisitMarkerWriteFailed); err != nil {
			level.Error(logger).Log("msg", "unable to upsert visit marker file content for block", "blockID", blockID, "err", err)
		}
		reader.Reset(visitMarkerFileContent)
	}
}

// markBlocksVisitedHeartBeat periodically re-uploads visit markers for the given blocks until
// ctx is cancelled or every tracked block has been removed from the bucket.
//
// Scope and lifetime:
//   - ctx should be a per-group context so the heartbeat stops as soon as that group's
//     compaction finishes. Callers typically derive it with context.WithCancel of a parent
//     context and arrange a cancel()/wg.Done() when planning/compaction of the group ends.
//   - When non-nil, wg is Done()'d when the heartbeat returns so the caller can Wait() for
//     all heartbeats to finish before returning.
//   - When non-nil, activeHeartbeats is incremented for the lifetime of this goroutine so
//     operators can observe heartbeat leaks via a gauge.
//
// Self-bounding: on each tick, if a marker upload for a block fails because the block
// directory no longer exists (i.e. hard-deleted by the blocks cleaner once compaction
// superseded the source blocks), that block is dropped from the refresh set so we do not
// recreate <ULID>/visit-mark.json and resurrect the block as an orphaned partial block.
// Once every block has been dropped, the heartbeat exits even if ctx is still live.
func markBlocksVisitedHeartBeat(
	ctx context.Context,
	bkt objstore.InstrumentedBucket,
	logger log.Logger,
	blocks []*metadata.Meta,
	compactorID string,
	blockVisitMarkerFileUpdateInterval time.Duration,
	blockVisitMarkerWriteFailed prometheus.Counter,
	activeHeartbeats prometheus.Gauge,
	wg *sync.WaitGroup,
) {
	if wg != nil {
		defer wg.Done()
	}
	if activeHeartbeats != nil {
		activeHeartbeats.Inc()
		defer activeHeartbeats.Dec()
	}

	// Work on a local copy so we can prune blocks that have been hard-deleted without
	// mutating the slice the caller may still be using.
	remaining := make([]*metadata.Meta, len(blocks))
	copy(remaining, blocks)

	blockIds := make([]string, 0, len(remaining))
	for _, block := range remaining {
		blockIds = append(blockIds, block.ULID.String())
	}
	blocksInfo := strings.Join(blockIds, ",")
	level.Info(logger).Log("msg", fmt.Sprintf("start heart beat for blocks: %s", blocksInfo))
	defer level.Info(logger).Log("msg", fmt.Sprintf("stop heart beat for blocks: %s", blocksInfo))

	ticker := time.NewTicker(blockVisitMarkerFileUpdateInterval)
	defer ticker.Stop()
heartBeat:
	for {
		level.Debug(logger).Log("msg", fmt.Sprintf("heart beat for blocks: %s", blocksInfo))
		blockVisitMarker := BlockVisitMarker{
			VisitTime:   time.Now().Unix(),
			CompactorID: compactorID,
			Version:     VisitMarkerVersion1,
		}
		remaining = refreshBlockVisitMarkers(ctx, bkt, logger, remaining, blockVisitMarker, blockVisitMarkerWriteFailed)
		if len(remaining) == 0 {
			// Every block we were tracking has been removed from the bucket, so there is
			// nothing left to refresh.
			break heartBeat
		}

		select {
		case <-ctx.Done():
			break heartBeat
		case <-ticker.C:
			continue
		}
	}
}

// refreshBlockVisitMarkers uploads the given marker for each block and returns the subset of
// blocks that still exist in the bucket. Blocks whose upload fails with a not-found error are
// dropped so subsequent heartbeat ticks do not resurrect them as orphaned partial blocks.
func refreshBlockVisitMarkers(
	ctx context.Context,
	bkt objstore.InstrumentedBucket,
	logger log.Logger,
	blocks []*metadata.Meta,
	marker BlockVisitMarker,
	blockVisitMarkerWriteFailed prometheus.Counter,
) []*metadata.Meta {
	visitMarkerFileContent, err := json.Marshal(marker)
	if err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return blocks
	}
	kept := blocks[:0]
	reader := bytes.NewReader(visitMarkerFileContent)
	for _, b := range blocks {
		blockID := b.ULID.String()
		visitMarkerFilePath := path.Join(blockID, BlockVisitMarkerFile)
		reader.Reset(visitMarkerFileContent)
		if err := bkt.Upload(ctx, visitMarkerFilePath, reader); err != nil {
			if bkt.IsObjNotFoundErr(err) {
				// The block is gone from the bucket, do not refresh its visit marker
				// (would otherwise resurrect it as an orphaned partial block).
				level.Info(logger).Log("msg", "stop refreshing visit marker for block that no longer exists", "blockID", blockID)
				continue
			}
			blockVisitMarkerWriteFailed.Inc()
			level.Error(logger).Log("msg", "unable to upsert visit marker file content for block", "blockID", blockID, "err", err)
		}
		kept = append(kept, b)
	}
	return kept
}
