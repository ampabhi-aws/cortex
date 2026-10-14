package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil. It panics when userID is empty: a "" prefix
// yields object keys at the bucket root (e.g. "/<ULID>/...") instead of inside
// a per-tenant prefix, which collapses the per-tenant namespace used by every
// storage component. The tenant resolver already rejects empty tenant IDs, so
// reaching this path with userID == "" indicates a programming error upstream
// and must fail closed.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		panic("bucket.NewUserBucketClient called with empty userID: refusing to map tenant onto bucket root")
	}

	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
