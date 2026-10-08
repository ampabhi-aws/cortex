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
	"github.com/thanos-io/thanos/pkg/block"
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
	// Work on a local copy so we can prune blocks whose meta.json has
	// been removed (e.g. because the block was hard-deleted after its
	// compaction group finished). This prevents the heartbeat from
	// recreating a <ULID>/visit-mark.json prefix for a block that no
	// longer exists, which would otherwise become un-collectable
	// permanent garbage with no deletion mark.
	activeBlocks := make([]*metadata.Meta, 0, len(blocks))
	activeBlocks = append(activeBlocks, blocks...)

	var blockIds []string
	for _, b := range activeBlocks {
		blockIds = append(blockIds, b.ULID.String())
	}
	blocksInfo := strings.Join(blockIds, ",")
	level.Info(logger).Log("msg", fmt.Sprintf("start heart beat for blocks: %s", blocksInfo))
	ticker := time.NewTicker(blockVisitMarkerFileUpdateInterval)
	defer ticker.Stop()
	first := true
heartBeat:
	for {
		level.Debug(logger).Log("msg", fmt.Sprintf("heart beat for blocks: %s", blocksInfo))

		// Fail-fast: on every tick after the initial one, drop any block
		// whose meta.json is gone from the bucket. If none remain, exit
		// the heartbeat instead of silently resurrecting block prefixes.
		// We skip the check on the very first iteration to match the
		// original behaviour of writing the first marker immediately
		// after Plan returns.
		if !first {
			activeBlocks = filterExistingBlocks(ctx, bkt, logger, activeBlocks)
			if len(activeBlocks) == 0 {
				level.Warn(logger).Log("msg", "all blocks disappeared, stopping heart beat", "blocks", blocksInfo)
				break heartBeat
			}
		}
		first = false

		blockVisitMarker := BlockVisitMarker{
			VisitTime:   time.Now().Unix(),
			CompactorID: compactorID,
			Version:     VisitMarkerVersion1,
		}
		markBlocksVisited(ctx, bkt, logger, activeBlocks, blockVisitMarker, blockVisitMarkerWriteFailed)

		select {
		case <-ctx.Done():
			break heartBeat
		case <-ticker.C:
			continue
		}
	}
	level.Info(logger).Log("msg", fmt.Sprintf("stop heart beat for blocks: %s", blocksInfo))
}

// filterExistingBlocks returns the subset of blocks whose meta.json still
// exists in the bucket. Blocks whose meta.json cannot be found are logged
// and removed from the slice so the heartbeat stops writing markers for
// them. On transient errors (e.g. network) the block is kept to avoid
// prematurely losing the lease.
func filterExistingBlocks(ctx context.Context, bkt objstore.Bucket, logger log.Logger, blocks []*metadata.Meta) []*metadata.Meta {
	if len(blocks) == 0 {
		return blocks
	}
	kept := make([]*metadata.Meta, 0, len(blocks))
	for i, b := range blocks {
		if ctx.Err() != nil {
			// Keep the remaining unchecked blocks on cancellation so we
			// don't drop them just because of a shutdown signal.
			kept = append(kept, blocks[i:]...)
			return kept
		}
		blockID := b.ULID.String()
		exists, err := bkt.Exists(ctx, path.Join(blockID, block.MetaFilename))
		if err != nil {
			// Keep the block on transient errors; the next heartbeat tick
			// will re-check. Only drop blocks on a confirmed not-found.
			level.Warn(logger).Log("msg", "failed to check block meta.json existence, keeping heart beat", "blockID", blockID, "err", err)
			kept = append(kept, b)
			continue
		}
		if !exists {
			level.Warn(logger).Log("msg", "block disappeared, stopping heart beat for it", "blockID", blockID)
			continue
		}
		kept = append(kept, b)
	}
	return kept
}
