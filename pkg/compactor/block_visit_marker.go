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

// markBlocksVisited uploads a visit marker for every block. It returns the
// first error encountered. Callers must treat a non-nil error as "lease not
// acquired" and skip the group, otherwise two compactors can hold overlapping
// "visit" state (CWE-367).
func markBlocksVisited(
	ctx context.Context,
	bkt objstore.Bucket,
	logger log.Logger,
	blocks []*metadata.Meta,
	marker BlockVisitMarker,
	blockVisitMarkerWriteFailed prometheus.Counter,
) error {
	visitMarkerFileContent, err := json.Marshal(marker)
	if err != nil {
		blockVisitMarkerWriteFailed.Inc()
		return err
	}
	reader := bytes.NewReader(visitMarkerFileContent)
	var firstErr error
	for _, block := range blocks {
		blockID := block.ULID.String()
		if err := UpdateBlockVisitMarker(ctx, bkt, blockID, reader, blockVisitMarkerWriteFailed); err != nil {
			level.Error(logger).Log("msg", "unable to upsert visit marker file content for block", "blockID", blockID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		reader.Reset(visitMarkerFileContent)
	}
	return firstErr
}

// verifyBlocksVisitedBy re-reads the visit marker for every block and returns
// an error if any marker is present but is not owned by compactorID. This is
// used as a post-write fence to narrow the TOCTOU window inherent in using a
// non-conditional object-store write to express the lease: when two
// compactors race to PUT the same marker, the loser will see the winner's
// compactorID on re-read and bow out. Read failures and missing markers are
// treated as inconclusive (not an exclusivity violation) and do not fail the
// check - a stronger fence requires conditional-put support in the object
// store wrapper.
func verifyBlocksVisitedBy(
	ctx context.Context,
	bkt objstore.InstrumentedBucketReader,
	logger log.Logger,
	blocks []*metadata.Meta,
	compactorID string,
	blockVisitMarkerTimeout time.Duration,
	blockVisitMarkerReadFailed prometheus.Counter,
) error {
	for _, block := range blocks {
		blockID := block.ULID.String()
		marker, err := ReadBlockVisitMarker(ctx, bkt, logger, blockID, blockVisitMarkerReadFailed)
		if err != nil {
			// Treat read errors (including NotFound after an eventual-consistency
			// gap) as inconclusive rather than a lease loss. Log and move on.
			level.Warn(logger).Log("msg", "unable to verify block visit marker after acquisition", "blockID", blockID, "err", err)
			continue
		}
		if marker.CompactorID != compactorID {
			return errors.Errorf("block %s lease held by compactor %q, not %s", blockID, marker.CompactorID, compactorID)
		}
		if !marker.isVisited(blockVisitMarkerTimeout) {
			return errors.Errorf("block %s lease expired before verification (visitTime=%d)", blockID, marker.VisitTime)
		}
	}
	return nil
}

// markBlocksVisitedHeartBeat refreshes the visit marker periodically for the
// lifetime of ctx. If marker writes keep failing for longer than
// blockVisitMarkerTimeout/2 (the fencing half-life), cancelHeartbeat is
// invoked so the heartbeat terminates instead of silently advertising a
// lease it can no longer refresh. cancelHeartbeat may be nil (e.g. in
// tests), in which case the previous best-effort behaviour is retained.
func markBlocksVisitedHeartBeat(
	ctx context.Context,
	bkt objstore.Bucket,
	logger log.Logger,
	blocks []*metadata.Meta,
	compactorID string,
	blockVisitMarkerFileUpdateInterval time.Duration,
	blockVisitMarkerTimeout time.Duration,
	blockVisitMarkerWriteFailed prometheus.Counter,
	cancelHeartbeat context.CancelFunc,
) {
	var blockIds []string
	for _, block := range blocks {
		blockIds = append(blockIds, block.ULID.String())
	}
	blocksInfo := strings.Join(blockIds, ",")
	level.Info(logger).Log("msg", fmt.Sprintf("start heart beat for blocks: %s", blocksInfo))
	if cancelHeartbeat != nil {
		defer cancelHeartbeat()
	}
	ticker := time.NewTicker(blockVisitMarkerFileUpdateInterval)
	defer ticker.Stop()
	lastSuccessfulRefresh := time.Now()
heartBeat:
	for {
		level.Debug(logger).Log("msg", fmt.Sprintf("heart beat for blocks: %s", blocksInfo))
		blockVisitMarker := BlockVisitMarker{
			VisitTime:   time.Now().Unix(),
			CompactorID: compactorID,
			Version:     VisitMarkerVersion1,
		}
		if err := markBlocksVisited(ctx, bkt, logger, blocks, blockVisitMarker, blockVisitMarkerWriteFailed); err != nil {
			// A heartbeat failure means another compactor could consider the
			// lease expired once blockVisitMarkerTimeout elapses. Terminate the
			// heartbeat once we have lost at least half of the timeout budget
			// so we fail fast instead of silently advertising a lease we can
			// no longer refresh.
			if blockVisitMarkerTimeout > 0 && cancelHeartbeat != nil && time.Since(lastSuccessfulRefresh) > blockVisitMarkerTimeout/2 {
				level.Error(logger).Log("msg", "aborting block visit heartbeat: lost block visit lease", "blocks", blocksInfo, "err", err, "since_last_refresh", time.Since(lastSuccessfulRefresh).String())
				cancelHeartbeat()
				break heartBeat
			}
		} else {
			lastSuccessfulRefresh = time.Now()
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
