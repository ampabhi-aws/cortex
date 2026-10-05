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

func TestUsersScanner_ScanUsers_ShouldSkipUsersForWhichOwnerCheckOrTenantDeletionCheckFailed(t *testing.T) {
	// The scanner must fail closed on ownership or tenant-deletion-mark errors so that the
	// compactor's blocks cleaner does not run destructive cleanup for a tenant whose
	// ownership (or deletion state) could not be determined on this replica.
	bucketClient := &bucket.ClientMock{}
	bucketClient.MockIter("", []string{"user-1", "user-2", "user-3"}, nil)
	bucketClient.MockExists(path.Join("user-1", TenantDeletionMarkPath), false, nil)
	bucketClient.MockExists(path.Join("user-3", TenantDeletionMarkPath), false, errors.New("fail"))

	isOwned := func(userID string) (bool, error) {
		if userID == "user-2" {
			return false, errors.New("failed to check if user is owned")
		}
		return true, nil
	}

	s := NewUsersScanner(bucketClient, isOwned, log.NewNopLogger())
	actual, deleted, err := s.ScanUsers(context.Background())
	require.NoError(t, err)
	// user-1 has no errors and is owned -> returned.
	// user-2 fails the ownership check -> skipped.
	// user-3 fails the deletion-mark check -> skipped.
	assert.Equal(t, []string{"user-1"}, actual)
	assert.Empty(t, deleted)
}
