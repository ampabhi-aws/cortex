package bucket

import (
	"context"
	"errors"
	"io"

	"github.com/thanos-io/objstore"
)

// errEmptyTenantID is returned by every operation of the bucket client produced
// by NewUserBucketClient when it is called with an empty userID. Fail-closed
// behaviour prevents an empty tenant ID from silently writing to the bucket
// root (which pollutes the shared object-storage namespace that compactors scan
// for tenants).
var errEmptyTenantID = errors.New("bucket: empty tenant ID")

// NewUserBucketClient returns a bucket client to use to access the storage on behalf of the provided user.
// The cfgProvider can be nil. When userID is empty the returned client fails every operation with an error
// rather than silently returning an unprefixed bucket (which would operate on the bucket root).
func NewUserBucketClient(userID string, bucket objstore.Bucket, cfgProvider TenantConfigProvider) objstore.InstrumentedBucket {
	if userID == "" {
		return failingBucketClient{}
	}

	// Inject the user/tenant prefix.
	bucket = NewPrefixedBucketClient(bucket, userID)

	// Inject the SSE config.
	return NewSSEBucketClient(userID, bucket, cfgProvider)
}

// failingBucketClient implements objstore.InstrumentedBucket and returns an
// error from every operation. It is used as the fail-closed return value from
// NewUserBucketClient when the tenant ID is empty.
type failingBucketClient struct{}

func (failingBucketClient) Close() error { return nil }

func (failingBucketClient) Upload(_ context.Context, _ string, _ io.Reader) error {
	return errEmptyTenantID
}

func (failingBucketClient) Delete(_ context.Context, _ string) error {
	return errEmptyTenantID
}

func (failingBucketClient) Name() string { return "cortex-fail-closed-empty-tenant" }

func (failingBucketClient) Iter(_ context.Context, _ string, _ func(string) error, _ ...objstore.IterOption) error {
	return errEmptyTenantID
}

func (failingBucketClient) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, errEmptyTenantID
}

func (failingBucketClient) GetRange(_ context.Context, _ string, _, _ int64) (io.ReadCloser, error) {
	return nil, errEmptyTenantID
}

func (failingBucketClient) Exists(_ context.Context, _ string) (bool, error) {
	return false, errEmptyTenantID
}

func (failingBucketClient) IsObjNotFoundErr(_ error) bool { return false }

func (failingBucketClient) Attributes(_ context.Context, _ string) (objstore.ObjectAttributes, error) {
	return objstore.ObjectAttributes{}, errEmptyTenantID
}

func (b failingBucketClient) WithExpectedErrs(_ objstore.IsOpFailureExpectedFunc) objstore.Bucket {
	return b
}

func (b failingBucketClient) ReaderWithExpectedErrs(_ objstore.IsOpFailureExpectedFunc) objstore.BucketReader {
	return b
}
