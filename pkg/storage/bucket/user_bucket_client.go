package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil. It panics if userID is empty as a defense-in-depth
// measure: an empty userID would collapse per-tenant storage prefixes onto the
// shared bucket root.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		panic("bucket: NewUserBucketClient called with empty userID")
	}
	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
