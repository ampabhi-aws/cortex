package compactor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
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

func markBlocksVisitedHeartBeat(ctx context.Context, bkt objstore.Bucket, logger log.Logger, blocks []*metadata.Meta, compactorID string, blockVisitMarkerFileUpdateInterval time.Duration, blockVisitMarkerWriteFailed prometheus.Counter) {
	var blockIds []string
	for _, block := range blocks {
		blockIds = append(blockIds, block.ULID.String())
	}
	blocksInfo := strings.Join(blockIds, ",")
	level.Info(logger).Log("msg", fmt.Sprintf("start heart beat for blocks: %s", blocksInfo))
	ticker := time.NewTicker(blockVisitMarkerFileUpdateInterval)
	defer ticker.Stop()
	// Track blocks that are still candidates for heartbeating. Blocks whose
	// source object has been hard-deleted (meta.json missing) are dropped so
	// that a stray visit-mark.json upload cannot resurrect a deleted block
	// directory. When no block remains, the heartbeat exits so the goroutine
	// does not outlive the data it is protecting.
	active := make([]*metadata.Meta, len(blocks))
	copy(active, blocks)
	first := true
heartBeat:
	for {
		level.Debug(logger).Log("msg", fmt.Sprintf("heart beat for blocks: %s", blocksInfo))

		if !first {
			// Only verify presence after the first write: the planner has
			// just produced this plan from blocks it already read from the
			// bucket, so the initial marker write is unconditional and
			// backward-compatible. From the second iteration onward, if
			// meta.json has disappeared, the cleaner has hard-deleted the
			// block and we must stop refreshing its marker.
			active = filterPresentBlocks(ctx, bkt, logger, active)
			if len(active) == 0 {
				level.Info(logger).Log("msg", fmt.Sprintf("all blocks for heart beat are gone, stopping: %s", blocksInfo))
				break heartBeat
			}
		}
		first = false

		blockVisitMarker := BlockVisitMarker{
			VisitTime:   time.Now().Unix(),
			CompactorID: compactorID,
			Version:     VisitMarkerVersion1,
		}
		markBlocksVisited(ctx, bkt, logger, active, blockVisitMarker, blockVisitMarkerWriteFailed)

		select {
		case <-ctx.Done():
			break heartBeat
		case <-ticker.C:
			continue
		}
	}
	level.Info(logger).Log("msg", fmt.Sprintf("stop heart beat for blocks: %s", blocksInfo))
}

// filterPresentBlocks returns the subset of blocks whose meta.json still
// exists in the bucket. A block whose meta.json has been removed has either
// been hard-deleted by the cleaner or never finished uploading, and the
// visit-marker heartbeat must stop refreshing its marker to avoid resurrecting
// the block directory as a partial block the cleaner can never remove.
func filterPresentBlocks(ctx context.Context, bkt objstore.Bucket, logger log.Logger, blocks []*metadata.Meta) []*metadata.Meta {
	if ctx.Err() != nil {
		return blocks
	}
	kept := make([]*metadata.Meta, 0, len(blocks))
	for _, block := range blocks {
		blockID := block.ULID.String()
		metaPath := path.Join(blockID, metadata.MetaFilename)
		exists, err := bkt.Exists(ctx, metaPath)
		if err != nil {
			if bkt.IsObjNotFoundErr(err) {
				level.Info(logger).Log("msg", "block meta no longer in bucket, dropping from visit-marker heartbeat", "blockID", blockID)
				continue
			}
			// On transient errors (e.g. network) keep the block in the
			// active set so that a flaky bucket does not stop the
			// heartbeat; the next tick will try again.
			level.Warn(logger).Log("msg", "failed to verify block presence for visit-marker heartbeat, keeping block", "blockID", blockID, "err", err)
			kept = append(kept, block)
			continue
		}
		if !exists {
			level.Info(logger).Log("msg", "block meta no longer in bucket, dropping from visit-marker heartbeat", "blockID", blockID)
			continue
		}
		kept = append(kept, block)
	}
	return kept
}
