package bucketindex

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"

	"github.com/go-kit/log"
	"github.com/pkg/errors"
	"github.com/thanos-io/objstore"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	"github.com/cortexproject/cortex/pkg/util/runutil"
)

// Hard limits applied when parsing a bucket index to defend against a maliciously
// crafted or corrupted <tenant>/bucket-index.json.gz object (e.g. a gzip bomb or a
// JSON document declaring an implausibly large number of blocks or segments). These
// values are intentionally generous: a bucket index in production is produced by the
// compactor and only lists completed blocks, so even very large deployments fit well
// within these bounds.
const (
	// MaxIndexCompressedSizeBytes bounds the number of bytes read from the
	// (potentially attacker-controlled) compressed object.
	MaxIndexCompressedSizeBytes = 32 * 1024 * 1024
	// MaxIndexUncompressedSizeBytes bounds the number of bytes consumed from the
	// gzip stream after decompression (defends against gzip bombs).
	MaxIndexUncompressedSizeBytes = 256 * 1024 * 1024
	// MaxBlocksPerIndex bounds the number of blocks (and block deletion marks)
	// that will be accepted in a single bucket index.
	MaxBlocksPerIndex = 1_000_000
	// MaxSegmentsPerBlock bounds the number of chunk segment files that may be
	// declared for a single block.
	MaxSegmentsPerBlock = 100_000
)

var (
	ErrIndexNotFound  = errors.New("bucket index not found")
	ErrIndexCorrupted = errors.New("bucket index corrupted")
)

// ReadIndex reads, parses and returns a bucket index from the bucket.
func ReadIndex(ctx context.Context, bkt objstore.Bucket, userID string, cfgProvider bucket.TenantConfigProvider, logger log.Logger) (*Index, error) {
	userBkt := bucket.NewUserBucketClient(userID, bkt, cfgProvider)

	// Get the bucket index.
	reader, err := userBkt.WithExpectedErrs(userBkt.IsObjNotFoundErr).Get(ctx, IndexCompressedFilename)
	if err != nil {
		if userBkt.IsObjNotFoundErr(err) {
			return nil, ErrIndexNotFound
		}
		return nil, errors.Wrap(err, "read bucket index")
	}
	defer runutil.CloseWithLogOnErr(logger, reader, "close bucket index reader")

	// Bound the number of compressed bytes we're willing to read from the bucket
	// (or, when the caching bucket is in use, from the metadata memcached). We
	// allow one extra byte so we can tell whether the limit was actually hit.
	limitedReader := io.LimitReader(reader, MaxIndexCompressedSizeBytes+1)

	// Read all the content.
	gzipReader, err := gzip.NewReader(limitedReader)
	if err != nil {
		return nil, ErrIndexCorrupted
	}
	defer runutil.CloseWithLogOnErr(logger, gzipReader, "close bucket index gzip reader")

	// Bound the number of decompressed bytes to defend against gzip bombs.
	boundedGzip := io.LimitReader(gzipReader, MaxIndexUncompressedSizeBytes+1)

	// Deserialize it.
	index := &Index{}
	d := json.NewDecoder(boundedGzip)
	if err := d.Decode(index); err != nil {
		return nil, ErrIndexCorrupted
	}

	// Validate the decoded content before returning it: a structurally valid but
	// implausibly large document could otherwise cause downstream allocation
	// storms (e.g. in Block.thanosMetaSegmentFiles).
	if len(index.Blocks) > MaxBlocksPerIndex || len(index.BlockDeletionMarks) > MaxBlocksPerIndex {
		return nil, ErrIndexCorrupted
	}
	for _, b := range index.Blocks {
		if b == nil {
			return nil, ErrIndexCorrupted
		}
		if b.SegmentsNum < 0 || b.SegmentsNum > MaxSegmentsPerBlock {
			return nil, ErrIndexCorrupted
		}
	}

	return index, nil
}

// WriteIndex uploads the provided index to the storage.
func WriteIndex(ctx context.Context, bkt objstore.Bucket, userID string, cfgProvider bucket.TenantConfigProvider, idx *Index) error {
	bkt = bucket.NewUserBucketClient(userID, bkt, cfgProvider)

	// Marshal the index.
	content, err := json.Marshal(idx)
	if err != nil {
		return errors.Wrap(err, "marshal bucket index")
	}

	// Compress it.
	var gzipContent bytes.Buffer
	gzip := gzip.NewWriter(&gzipContent)
	gzip.Name = IndexFilename

	if _, err := gzip.Write(content); err != nil {
		return errors.Wrap(err, "gzip bucket index")
	}
	if err := gzip.Close(); err != nil {
		return errors.Wrap(err, "close gzip bucket index")
	}

	// Upload the index to the storage.
	if err := bkt.Upload(ctx, IndexCompressedFilename, &gzipContent); err != nil {
		return errors.Wrap(err, "upload bucket index")
	}

	return nil
}

// DeleteIndex deletes the bucket index from the storage. No error is returned if the index
// does not exist.
func DeleteIndex(ctx context.Context, bkt objstore.Bucket, userID string, cfgProvider bucket.TenantConfigProvider) error {
	bkt = bucket.NewUserBucketClient(userID, bkt, cfgProvider)

	err := bkt.Delete(ctx, IndexCompressedFilename)
	if err != nil && !bkt.IsObjNotFoundErr(err) {
		return errors.Wrap(err, "delete bucket index")
	}
	return nil
}
