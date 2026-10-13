package cache

import (
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/golang/snappy"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

type snappyCache struct {
	next   Cache
	logger log.Logger
}

// NewSnappy makes a new snappy encoding cache wrapper.
func NewSnappy(next Cache, logger log.Logger) Cache {
	return &snappyCache{
		next:   next,
		logger: logger,
	}
}

func (s *snappyCache) Store(ctx context.Context, keys []string, bufs [][]byte) {
	cs := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		c := snappy.Encode(nil, buf)
		cs = append(cs, c)
	}
	s.next.Store(ctx, keys, cs)
}

// maxDecodedSize is an upper bound on the uncompressed size of a single cache
// entry we are willing to allocate for. It mirrors memcached's default
// max-item-size (1 MiB) with generous head-room for a well-formed snappy
// payload, and is well below the 4 GiB cap enforced by the snappy decoder
// itself. Entries whose varint header declares a larger size are treated as
// a cache miss rather than being decoded, so a poisoned cache cannot force
// the process to allocate gigabytes before the body is validated.
const maxDecodedSize = 64 * 1024 * 1024 // 64 MiB

func (s *snappyCache) Fetch(ctx context.Context, keys []string) ([]string, [][]byte, []string) {
	found, bufs, missing := s.next.Fetch(ctx, keys)
	fs := make([]string, 0, len(found))
	ds := make([][]byte, 0, len(bufs))
	for i, buf := range bufs {
		// Pre-check the declared uncompressed length against a cap before
		// handing the buffer to snappy.Decode, which allocates the full
		// declared size before validating the body.
		if size, err := snappy.DecodedLen(buf); err != nil || size < 0 || size > maxDecodedSize {
			level.Error(util_log.WithContext(ctx, s.logger)).Log("msg", "skipping cache entry with invalid or oversized snappy header", "err", err, "declared_size", size, "max", maxDecodedSize)
			missing = append(missing, found[i])
			continue
		}
		d, err := snappy.Decode(nil, buf)
		if err != nil {
			level.Error(util_log.WithContext(ctx, s.logger)).Log("msg", "failed to decode cache entry", "err", err)
			// Drop only the offending entry rather than discarding the
			// whole batch, so one poisoned key does not disable caching
			// for every key fetched with it.
			missing = append(missing, found[i])
			continue
		}
		fs = append(fs, found[i])
		ds = append(ds, d)
	}
	return fs, ds, missing
}

func (s *snappyCache) Stop() {
	s.next.Stop()
}
