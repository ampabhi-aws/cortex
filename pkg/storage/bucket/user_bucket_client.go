package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil.
//
// It panics if userID is empty: the tenant resolver is expected to reject
// empty tenant IDs upstream, and silently using an empty prefix would make
// the empty tenant's object keys collapse onto the shared parent namespace
// of every tenant (e.g. on the filesystem backend filepath.Join cleans away
// empty path segments). Failing closed here prevents cross-tenant key-space
// collapse if an empty userID ever reaches this helper.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		panic("bucket.NewUserBucketClient called with empty userID")
	}
	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
