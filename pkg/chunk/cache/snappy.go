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

// maxSnappyDecodedSize bounds the decoded length declared in a snappy entry's
// varint header before any allocation happens. Cache contents are only
// semi-trusted (shared memcached/redis), so we refuse to allocate huge buffers
// based on the entry's own self-reported length. 64 MiB comfortably covers any
// legitimate cached payload (memcached's default item limit is 1 MiB) while
// preventing the ~4 GiB allocation that an attacker-planted header could
// otherwise force.
const maxSnappyDecodedSize = 64 * 1024 * 1024

func (s *snappyCache) Fetch(ctx context.Context, keys []string) ([]string, [][]byte, []string) {
	found, bufs, missing := s.next.Fetch(ctx, keys)
	ds := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		// Bound the decoded size before snappy.Decode allocates it, so a
		// corrupt or malicious cache entry cannot force a huge allocation.
		if size, err := snappy.DecodedLen(buf); err != nil {
			level.Error(util_log.WithContext(ctx, s.logger)).Log("msg", "failed to decode cache entry", "err", err)
			return nil, nil, keys
		} else if size > maxSnappyDecodedSize {
			level.Error(util_log.WithContext(ctx, s.logger)).Log("msg", "failed to decode cache entry", "err", "decoded size exceeds maximum", "size", size, "max", maxSnappyDecodedSize)
			return nil, nil, keys
		}
		d, err := snappy.Decode(nil, buf)
		if err != nil {
			level.Error(util_log.WithContext(ctx, s.logger)).Log("msg", "failed to decode cache entry", "err", err)
			return nil, nil, keys
		}
		ds = append(ds, d)
	}
	return found, ds, missing
}

func (s *snappyCache) Stop() {
	s.next.Stop()
}
