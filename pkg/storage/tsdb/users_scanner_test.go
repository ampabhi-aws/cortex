package tsdb

import (
	"context"
	"errors"
	"path"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
)

func TestUsersScanner_ScanUsers_ShouldReturnedOwnedUsersOnly(t *testing.T) {
	bucketClient := &bucket.ClientMock{}
	bucketClient.MockIter("", []string{"user-1", "user-2", "user-3", "user-4"}, nil)
	bucketClient.MockExists(path.Join("user-1", TenantDeletionMarkPath), false, nil)
	bucketClient.MockExists(path.Join("user-3", TenantDeletionMarkPath), true, nil)

	isOwned := func(userID string) (bool, error) {
		return userID == "user-1" || userID == "user-3", nil
	}

	s := NewUsersScanner(bucketClient, isOwned, log.NewNopLogger())
	actual, deleted, err := s.ScanUsers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, actual)
	assert.Equal(t, []string{"user-3"}, deleted)

}

func TestUsersScanner_ScanUsers_ShouldDropUsersForWhichOwnerCheckOrTenantDeletionCheckFailed(t *testing.T) {
	// When isOwned returns an error we must fail closed and drop the tenant from
	// the returned lists for this cycle, otherwise every compactor replica would
	// end up concurrently cleaning every tenant on a ring/KV fault.
	// Likewise when the tenant-deletion-mark lookup errors, the tenant must not
	// be classified as "active".
	bucketClient := &bucket.ClientMock{}
	bucketClient.MockIter("", []string{"user-1", "user-2"}, nil)
	bucketClient.MockExists(path.Join("user-1", TenantDeletionMarkPath), false, nil)
	bucketClient.MockExists(path.Join("user-2", TenantDeletionMarkPath), false, errors.New("fail"))

	isOwned := func(userID string) (bool, error) {
		if userID == "user-1" {
			return false, errors.New("failed to check if user is owned")
		}
		return true, nil
	}

	s := NewUsersScanner(bucketClient, isOwned, log.NewNopLogger())
	actual, deleted, err := s.ScanUsers(context.Background())
	require.NoError(t, err)
	assert.Empty(t, actual)
	assert.Empty(t, deleted)
}
