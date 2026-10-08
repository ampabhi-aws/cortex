package ingester

import (
	"encoding/binary"
	"hash"
	"math"
	"sync"
	"time"

	"github.com/cespare/xxhash"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/util"
)

const (
	numActiveSeriesStripes = 512

	// maxActiveSeriesEntriesPerFingerprint caps the number of distinct label
	// sets we are willing to keep in a single hash bucket. Even with an
	// injective fingerprint, a hostile tenant could still try to find hash
	// collisions; capping the bucket size guarantees that scans and
	// per-entry purge work on the active-series index stay bounded.
	maxActiveSeriesEntriesPerFingerprint = 32
)

// ActiveSeries is keeping track of recently active series for a single tenant.
type ActiveSeries struct {
	stripes [numActiveSeriesStripes]activeSeriesStripe
}

// activeSeriesStripe holds a subset of the series timestamps for a single tenant.
type activeSeriesStripe struct {
	// Unix nanoseconds. Only used by purge. Zero = unknown.
	// Updated in purge and when old timestamp is used when updating series (in this case, oldestEntryTs is updated
	// without holding the lock -- hence the atomic).
	oldestEntryTs atomic.Int64

	mu     sync.RWMutex
	refs   map[uint64][]activeSeriesEntry
	active int // Number of active entries in this stripe. Only decreased during purge or clear.
}

// activeSeriesEntry holds a timestamp for single series.
type activeSeriesEntry struct {
	lbs   labels.Labels
	nanos *atomic.Int64 // Unix timestamp in nanoseconds. Needs to be a pointer because we don't store pointers to entries in the stripe.
}

func NewActiveSeries() *ActiveSeries {
	c := &ActiveSeries{}

	// Stripes are pre-allocated so that we only read on them and no lock is required.
	for i := 0; i < numActiveSeriesStripes; i++ {
		c.stripes[i].refs = map[uint64][]activeSeriesEntry{}
	}

	return c
}

// Updates series timestamp to 'now'. Function is called to make a copy of labels if entry doesn't exist yet.
func (c *ActiveSeries) UpdateSeries(series labels.Labels, now time.Time, labelsCopy func(labels.Labels) labels.Labels) {
	fp := fingerprint(series)
	stripeID := fp % numActiveSeriesStripes

	c.stripes[stripeID].updateSeriesTimestamp(now, series, fp, labelsCopy)
}

var hashPool = sync.Pool{New: func() interface{} { return xxhash.New() }}

// fingerprint computes an injective 64-bit hash of the label set by
// length-prefixing each component. Without length prefixing, a tenant could
// embed the Prometheus separator byte (0xFF) in a label value and craft
// distinct label sets that share the same serialized byte stream, forcing
// unbounded hash-bucket collisions and quadratic ingestion/purge cost in the
// active-series index. Length-prefixing closes that pre-image family.
func fingerprint(series labels.Labels) uint64 {
	sum := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(sum)

	sum.Reset()
	var n [8]byte
	for _, label := range series {
		binary.LittleEndian.PutUint64(n[:], uint64(len(label.Name)))
		_, _ = sum.Write(n[:])
		_, _ = sum.Write(util.YoloBuf(label.Name))
		binary.LittleEndian.PutUint64(n[:], uint64(len(label.Value)))
		_, _ = sum.Write(n[:])
		_, _ = sum.Write(util.YoloBuf(label.Value))
	}

	return sum.Sum64()
}

// Purge removes expired entries from the cache. This function should be called
// periodically to avoid memory leaks.
func (c *ActiveSeries) Purge(keepUntil time.Time) {
	for s := 0; s < numActiveSeriesStripes; s++ {
		c.stripes[s].purge(keepUntil)
	}
}

// nolint // Linter reports that this method is unused, but it is.
func (c *ActiveSeries) clear() {
	for s := 0; s < numActiveSeriesStripes; s++ {
		c.stripes[s].clear()
	}
}

func (c *ActiveSeries) Active() int {
	total := 0
	for s := 0; s < numActiveSeriesStripes; s++ {
		total += c.stripes[s].getActive()
	}
	return total
}

func (s *activeSeriesStripe) updateSeriesTimestamp(now time.Time, series labels.Labels, fingerprint uint64, labelsCopy func(labels.Labels) labels.Labels) {
	nowNanos := now.UnixNano()

	e := s.findEntryForSeries(fingerprint, series)
	entryTimeSet := false
	if e == nil {
		e, entryTimeSet = s.findOrCreateEntryForSeries(fingerprint, series, nowNanos, labelsCopy)
	}

	if !entryTimeSet {
		if prev := e.Load(); nowNanos > prev {
			entryTimeSet = e.CompareAndSwap(prev, nowNanos)
		}
	}

	if entryTimeSet {
		for prevOldest := s.oldestEntryTs.Load(); nowNanos < prevOldest; {
			// If recent purge already removed entries older than "oldest entry timestamp", setting this to 0 will make
			// sure that next purge doesn't take the shortcut route.
			if s.oldestEntryTs.CompareAndSwap(prevOldest, 0) {
				break
			}
		}
	}
}

func (s *activeSeriesStripe) findEntryForSeries(fingerprint uint64, series labels.Labels) *atomic.Int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if already exists within the entries.
	for ix, entry := range s.refs[fingerprint] {
		if labels.Equal(entry.lbs, series) {
			return s.refs[fingerprint][ix].nanos
		}
	}

	return nil
}

func (s *activeSeriesStripe) findOrCreateEntryForSeries(fingerprint uint64, series labels.Labels, nowNanos int64, labelsCopy func(labels.Labels) labels.Labels) (*atomic.Int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already exists within the entries.
	for ix, entry := range s.refs[fingerprint] {
		if labels.Equal(entry.lbs, series) {
			return s.refs[fingerprint][ix].nanos, false
		}
	}

	// Cap the per-fingerprint bucket so that bucket scans and purge work
	// can never become super-linear if an attacker finds (or forces) a
	// hash collision. The returned atomic.Int64 is still a valid sink,
	// but the entry is not inserted; the caller treats this as a
	// best-effort active-series update.
	if len(s.refs[fingerprint]) >= maxActiveSeriesEntriesPerFingerprint {
		return atomic.NewInt64(nowNanos), true
	}

	s.active++
	e := activeSeriesEntry{
		lbs:   labelsCopy(series),
		nanos: atomic.NewInt64(nowNanos),
	}

	s.refs[fingerprint] = append(s.refs[fingerprint], e)

	return e.nanos, true
}

// nolint // Linter reports that this method is unused, but it is.
func (s *activeSeriesStripe) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oldestEntryTs.Store(0)
	s.refs = map[uint64][]activeSeriesEntry{}
	s.active = 0
}

func (s *activeSeriesStripe) purge(keepUntil time.Time) {
	keepUntilNanos := keepUntil.UnixNano()
	if oldest := s.oldestEntryTs.Load(); oldest > 0 && keepUntilNanos <= oldest {
		// Nothing to do.
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	active := 0

	oldest := int64(math.MaxInt64)
	for fp, entries := range s.refs {
		// Since we do expect very few fingerprint collisions, we
		// have an optimized implementation for the common case.
		if len(entries) == 1 {
			ts := entries[0].nanos.Load()
			if ts < keepUntilNanos {
				delete(s.refs, fp)
				continue
			}

			active++
			if ts < oldest {
				oldest = ts
			}
			continue
		}

		// We have more entries, which means there's a collision,
		// so we have to iterate over the entries. Build a new slice in
		// one pass instead of splicing in place, which would be O(N) per
		// removal and O(N^2) per bucket under the write lock.
		kept := entries[:0]
		for i := range entries {
			ts := entries[i].nanos.Load()
			if ts < keepUntilNanos {
				continue
			}
			if ts < oldest {
				oldest = ts
			}
			kept = append(kept, entries[i])
		}
		// Zero out any trailing references so the underlying array can be
		// garbage-collected.
		for i := len(kept); i < len(entries); i++ {
			entries[i] = activeSeriesEntry{}
		}
		entries = kept

		// Either update or delete the entries in the map
		if cnt := len(entries); cnt == 0 {
			delete(s.refs, fp)
		} else {
			active += cnt
			s.refs[fp] = entries
		}
	}

	if oldest == math.MaxInt64 {
		s.oldestEntryTs.Store(0)
	} else {
		s.oldestEntryTs.Store(oldest)
	}
	s.active = active
}

func (s *activeSeriesStripe) getActive() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.active
}
