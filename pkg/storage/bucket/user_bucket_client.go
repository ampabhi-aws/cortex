package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil.
//
// NewUserBucketClient panics if userID is empty. An empty tenant prefix would
// cause objects to be written at the bucket root (outside any tenant prefix),
// collapsing per-tenant storage isolation. Callers must ensure the tenant ID
// has been validated (see pkg/tenant.ValidTenantID) before calling.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		panic("bucket.NewUserBucketClient: empty tenant ID is not allowed")
	}

	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
