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

// ErrorBlockVisitMarkerOwnedByOther is returned by the conditional update helpers
// when the on-bucket visit marker is currently owned by a different compactor and
// has not yet expired (its visit time is within -compactor.block-visit-marker-timeout).
// Callers must treat this as "another compactor already owns this block/group" and
// must NOT proceed to compact the affected blocks.
var ErrorBlockVisitMarkerOwnedByOther = errors.New("block visit marker owned by another live compactor")

func UpdateBlockVisitMarker(ctx context.Context, bkt objstore.Bucket, blockID string, reader io.Reader, blockVisitMarkerWriteFailed prometheus.Counter) error {
	blockVisitMarkerFilePath := path.Join(blockID, BlockVisitMarkerFile)
	if err := bkt.Upload(ctx, blockVisitMarkerFilePath, reader); err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return err
	}
	return nil
}

// tryClaimBlockVisitMarker performs a read-before-write "claim" of a block visit
// marker. It refuses to overwrite a marker that is currently owned by a
// different compactor and whose visit time is still within blockVisitMarkerTimeout.
// It is not fully atomic with respect to concurrent writers (object storage
// here does not expose a conditional PUT), but it closes the common
// read-then-blind-write TOCTOU window by re-checking ownership on every write
// (initial claim and heartbeat refresh), so a losing compactor stops instead
// of silently overwriting the winner's claim.
func tryClaimBlockVisitMarker(
	ctx context.Context,
	bkt objstore.Bucket,
	instrBkt objstore.InstrumentedBucketReader,
	logger log.Logger,
	blockID string,
	marker BlockVisitMarker,
	blockVisitMarkerTimeout time.Duration,
	reader io.Reader,
	blockVisitMarkerReadFailed prometheus.Counter,
	blockVisitMarkerWriteFailed prometheus.Counter,
) error {
	existing, err := ReadBlockVisitMarker(ctx, instrBkt, logger, blockID, blockVisitMarkerReadFailed)
	if err != nil && !errors.Is(err, ErrorBlockVisitMarkerNotFound) {
		// Unmarshal/version/transient errors: fall through and attempt to
		// (re)claim. If storage is permanently broken the Upload below will
		// surface the same class of error to the caller.
		level.Warn(logger).Log("msg", "unable to read existing block visit marker before claim, attempting to claim anyway", "blockID", blockID, "err", err)
	} else if err == nil && existing != nil {
		if existing.CompactorID != marker.CompactorID && existing.isVisited(blockVisitMarkerTimeout) {
			return errors.Wrapf(ErrorBlockVisitMarkerOwnedByOther, "block %s is currently owned by compactor %s", blockID, existing.CompactorID)
		}
	}
	return UpdateBlockVisitMarker(ctx, bkt, blockID, reader, blockVisitMarkerWriteFailed)
}

// markBlocksVisited attempts to claim/refresh the visit marker on every block
// in blocks on behalf of marker.CompactorID. It returns true only if every
// block was successfully claimed by us; it returns false if any block was
// already owned by a different live compactor or if any upload failed. Callers
// that take out an initial claim (e.g. ShuffleShardingGrouper) MUST check this
// return value and skip the group when it is false — otherwise two compactors
// in the same tenant sub-ring can both believe they own the group and both
// compact the same source blocks.
func markBlocksVisited(
	ctx context.Context,
	bkt objstore.Bucket,
	instrBkt objstore.InstrumentedBucketReader,
	logger log.Logger,
	blocks []*metadata.Meta,
	marker BlockVisitMarker,
	blockVisitMarkerTimeout time.Duration,
	blockVisitMarkerReadFailed prometheus.Counter,
	blockVisitMarkerWriteFailed prometheus.Counter,
) bool {
	visitMarkerFileContent, err := json.Marshal(marker)
	if err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return false
	}
	reader := bytes.NewReader(visitMarkerFileContent)
	ok := true
	for _, block := range blocks {
		blockID := block.ULID.String()
		if err := tryClaimBlockVisitMarker(ctx, bkt, instrBkt, logger, blockID, marker, blockVisitMarkerTimeout, reader, blockVisitMarkerReadFailed, blockVisitMarkerWriteFailed); err != nil {
			if errors.Is(err, ErrorBlockVisitMarkerOwnedByOther) {
				level.Info(logger).Log("msg", "refusing to overwrite visit marker owned by another live compactor", "blockID", blockID, "err", err)
			} else {
				level.Error(logger).Log("msg", "unable to upsert visit marker file content for block", "blockID", blockID, "err", err)
			}
			ok = false
		}
		reader.Reset(visitMarkerFileContent)
	}
	return ok
}

func markBlocksVisitedHeartBeat(ctx context.Context, bkt objstore.Bucket, instrBkt objstore.InstrumentedBucketReader, logger log.Logger, blocks []*metadata.Meta, compactorID string, blockVisitMarkerFileUpdateInterval time.Duration, blockVisitMarkerTimeout time.Duration, blockVisitMarkerReadFailed prometheus.Counter, blockVisitMarkerWriteFailed prometheus.Counter) {
	var blockIds []string
	for _, block := range blocks {
		blockIds = append(blockIds, block.ULID.String())
	}
	blocksInfo := strings.Join(blockIds, ",")
	level.Info(logger).Log("msg", fmt.Sprintf("start heart beat for blocks: %s", blocksInfo))
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
		if !markBlocksVisited(ctx, bkt, instrBkt, logger, blocks, blockVisitMarker, blockVisitMarkerTimeout, blockVisitMarkerReadFailed, blockVisitMarkerWriteFailed) {
			// Another compactor has taken ownership of at least one block in
			// this group (or the write failed). Stop refreshing so we do not
			// trample the current owner's claim; the losing compaction will
			// be aborted by ShuffleShardingPlanner.Plan's ownership re-check.
			level.Warn(logger).Log("msg", fmt.Sprintf("stopping heart beat because visit marker ownership was lost for one or more blocks: %s", blocksInfo))
			break heartBeat
		}

		select {
		case <-ctx.Done():
			break heartBeat
		case <-ticker.C:
			continue
		}
	}
	level.Info(logger).Log("msg", fmt.Sprintf("stop heart beat for blocks: %s", blocksInfo))
}
