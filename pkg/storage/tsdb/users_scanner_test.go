package tsdb

import (
	"context"
	"errors"
	"path"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
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

// TestUsersScanner_ScanUsers_ShouldFailClosedOnOwnershipError verifies that when the
// ownership check (e.g. a compactor ring lookup) returns an error for a tenant, the
// scanner drops that tenant from the returned list instead of treating it as owned.
// This is required so that a transient ring/KV fault does not cause every compactor
// replica to simultaneously consider itself the owner of every tenant and race on
// block deletion and per-tenant bucket index writes. Cleanup is idempotent across
// cycles, so deferring the tenant to the next scan is strictly safer than fail-open.
func TestUsersScanner_ScanUsers_ShouldFailClosedOnOwnershipError(t *testing.T) {
	bucketClient := &bucket.ClientMock{}
	bucketClient.MockIter("", []string{"user-1", "user-2"}, nil)

	isOwned := func(userID string) (bool, error) {
		return false, errors.New("failed to check if user is owned")
	}

	skipped := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_skipped"})

	s := NewUsersScanner(bucketClient, isOwned, log.NewNopLogger())
	s.SetOwnershipFailedCounter(skipped)
	actual, deleted, err := s.ScanUsers(context.Background())
	require.NoError(t, err)
	assert.Empty(t, actual)
	assert.Empty(t, deleted)
	assert.Equal(t, float64(2), promtestutil.ToFloat64(skipped))
}

// TestUsersScanner_ScanUsers_ShouldReturnUsersForWhichTenantDeletionCheckFailed verifies
// that an error reading the tenant-deletion mark does not drop the tenant: unlike the
// ownership check, the tenant-deletion-mark read failure means we cannot distinguish
// "active" from "marked for deletion" but the tenant is still (per the ownership check)
// ours to handle, and treating it as a regular active tenant is the safer default (the
// only tenant-deletion-mark-driven code path is the explicit full-tenant deletion
// performed by BlocksCleaner.deleteUserMarkedForDeletion, which requires a positive
// mark read, not a failed one).
func TestUsersScanner_ScanUsers_ShouldReturnUsersForWhichTenantDeletionCheckFailed(t *testing.T) {
	expected := []string{"user-1", "user-2"}

	bucketClient := &bucket.ClientMock{}
	bucketClient.MockIter("", expected, nil)
	bucketClient.MockExists(path.Join("user-1", TenantDeletionMarkPath), false, nil)
	bucketClient.MockExists(path.Join("user-2", TenantDeletionMarkPath), false, errors.New("fail"))

	isOwned := func(userID string) (bool, error) {
		return true, nil
	}

	s := NewUsersScanner(bucketClient, isOwned, log.NewNopLogger())
	actual, deleted, err := s.ScanUsers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
	assert.Empty(t, deleted)
}
