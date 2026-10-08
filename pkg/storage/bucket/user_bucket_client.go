package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil.
//
// NOTE: userID must be non-empty. An empty userID would make the prefixed
// client write to the bucket root (the shared namespace parent of all
// per-tenant prefixes) and must be rejected upstream (see ValidTenantID).
// NewPrefixedBucketClient panics on an empty prefix as a defence against
// callers that forget to validate the tenant ID.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
