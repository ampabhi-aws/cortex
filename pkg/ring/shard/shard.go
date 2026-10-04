package shard

import (
	"crypto/md5"
	"encoding/binary"
	"math"
	"reflect"
	"unsafe"
)

var (
	seedSeparator = []byte{0}
)

// ShuffleShardSeed returns seed for random number generator, computed from provided identifier.
func ShuffleShardSeed(identifier, zone string) int64 {
	// Use the identifier to compute a hash we'll use to seed the random.
	hasher := md5.New()
	hasher.Write(yoloBuf(identifier)) // nolint:errcheck
	if zone != "" {
		hasher.Write(seedSeparator) // nolint:errcheck
		hasher.Write(yoloBuf(zone)) // nolint:errcheck
	}
	checksum := hasher.Sum(nil)

	// Generate the seed based on the first 64 bits of the checksum.
	return int64(binary.BigEndian.Uint64(checksum))
}

// ShuffleShardExpectedInstancesPerZone returns the number of instances that should be selected for each
// zone when zone-aware replication is enabled. The algorithm expects the shard size to be divisible
// by the number of zones, in order to have nodes balanced across zones. If it's not, we do round up.
func ShuffleShardExpectedInstancesPerZone(shardSize, numZones int) int {
	return int(math.Ceil(float64(shardSize) / float64(numZones)))
}

// ShuffleShardExpectedInstances returns the total number of instances that should be selected for a given
// tenant. If zone-aware replication is disabled, the input numZones should be 1.
func ShuffleShardExpectedInstances(shardSize, numZones int) int {
	return ShuffleShardExpectedInstancesPerZone(shardSize, numZones) * numZones
}

// yoloBuf will return an unsafe pointer to the backing bytes of s, as the name
// yolo.yoloBuf implies use at your own risk. The returned slice has cap == len
// and must be treated as read-only: writing through it (directly, via append
// within cap, or via a full-slice reslice) is undefined behaviour because Go
// string bytes are immutable.
//
// We cannot simply pun the 2-word string header as a 3-word slice header via
// `*((*[]byte)(unsafe.Pointer(&s)))`: that reads one word past the string
// header and installs an uninitialised word as the slice capacity, violating
// the 0 <= len <= cap invariant. Instead we build the slice header explicitly
// so that cap == len.
func yoloBuf(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var b []byte
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}
