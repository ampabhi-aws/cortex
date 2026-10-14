package bucket

import (
	"github.com/thanos-io/objstore"
)

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil.
//
// The userID must be non-empty: tenant-scoped object keys are built as
// prefix+"/"+name, so an empty userID would collapse the per-tenant prefix to
// the shared parent scope. Callers must validate the tenant ID before calling
// this function (the tenant resolver already rejects empty tenant IDs); this
// panic is defence in depth against a programmer error.
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		panic("bucket: NewUserBucketClient called with empty userID")
	}
	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}
