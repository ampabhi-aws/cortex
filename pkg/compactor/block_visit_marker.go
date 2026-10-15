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
	// blockVisitMarkerFutureAllowance is the maximum amount of clock skew we tolerate
	// in a visit marker's VisitTime before treating the marker as untrustworthy. Any
	// marker whose VisitTime is more than this far in the future (e.g. because of
	// clock skew on the writer or a tampered/corrupt marker file) is ignored by the
	// visited check so that the group is not stalled forever.
	blockVisitMarkerFutureAllowance = 5 * time.Minute
)

var (
	ErrorBlockVisitMarkerNotFound        = errors.New("block visit marker not found")
	ErrorUnmarshalBlockVisitMarker       = errors.New("unmarshal block visit marker JSON")
	ErrorBlockVisitMarkerVersionMismatch = errors.New("unexpected block visit marker version")
)

type BlockVisitMarker struct {
	CompactorID string `json:"compactorID"`
	// VisitTime is a unix timestamp of when the block was visited (mark updated).
	VisitTime int64 `json:"visitTime"`
	// Version of the file.
	Version int `json:"version"`
}

// effectiveExpiry returns the time at which the marker should be considered
// expired, bounded so that a far-future VisitTime cannot keep the marker
// "valid" beyond now+blockVisitMarkerTimeout. If VisitTime is more than the
// small allowance in the future it is treated as invalid (zero time), which
// callers interpret as not-visited.
func (b *BlockVisitMarker) effectiveExpiry(blockVisitMarkerTimeout time.Duration) time.Time {
	now := time.Now()
	visit := time.Unix(b.VisitTime, 0)
	// Reject markers whose VisitTime is implausibly far in the future.
	if visit.After(now.Add(blockVisitMarkerFutureAllowance)) {
		return time.Time{}
	}
	expiry := visit.Add(blockVisitMarkerTimeout)
	// Cap the effective expiry so that a VisitTime slightly in the future (within
	// the allowance) still cannot keep the marker alive longer than one timeout
	// window from now.
	if maxExpiry := now.Add(blockVisitMarkerTimeout); expiry.After(maxExpiry) {
		expiry = maxExpiry
	}
	return expiry
}

func (b *BlockVisitMarker) isVisited(blockVisitMarkerTimeout time.Duration) bool {
	expiry := b.effectiveExpiry(blockVisitMarkerTimeout)
	if expiry.IsZero() {
		return false
	}
	return time.Now().Before(expiry)
}

func (b *BlockVisitMarker) isVisitedByCompactor(blockVisitMarkerTimeout time.Duration, compactorID string) bool {
	if b.CompactorID != compactorID {
		return false
	}
	expiry := b.effectiveExpiry(blockVisitMarkerTimeout)
	if expiry.IsZero() {
		return false
	}
	return time.Now().Before(expiry)
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
		blockVisitMarkerReadFailed.Inc()
		return nil, errors.Wrapf(ErrorBlockVisitMarkerVersionMismatch, "block visit marker file: %s, version %d, expected %d", visitMarkerFile, blockVisitMarker.Version, VisitMarkerVersion1)
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
heartBeat:
	for {
		level.Debug(logger).Log("msg", fmt.Sprintf("heart beat for blocks: %s", blocksInfo))
		blockVisitMarker := BlockVisitMarker{
			VisitTime:   time.Now().Unix(),
			CompactorID: compactorID,
			Version:     VisitMarkerVersion1,
		}
		markBlocksVisited(ctx, bkt, logger, blocks, blockVisitMarker, blockVisitMarkerWriteFailed)

		select {
		case <-ctx.Done():
			break heartBeat
		case <-ticker.C:
			continue
		}
	}
	level.Info(logger).Log("msg", fmt.Sprintf("stop heart beat for blocks: %s", blocksInfo))
}
