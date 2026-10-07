package tsdb

import (
	"context"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/thanos-io/objstore"
)

// AllUsers returns true to each call and should be used whenever the UsersScanner should not filter out
// any user due to sharding.
func AllUsers(_ string) (bool, error) {
	return true, nil
}

type UsersScanner struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	isOwned      func(userID string) (bool, error)
	// strictOwnership makes ScanUsers skip tenants when the ownership check
	// returns an error (fail-closed). When false, tenants are retained on
	// ownership-check errors (fail-open), preserving the historical lenient
	// behaviour expected by metrics-only / read-only scans (e.g. querier
	// bucket scan, thanosconvert).
	strictOwnership bool
}

// NewUsersScanner creates a UsersScanner that retains a tenant when the
// ownership check returns an error (fail-open). Prefer
// NewUsersScannerStrict for destructive consumers like the blocks cleaner.
func NewUsersScanner(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), logger log.Logger) *UsersScanner {
	return &UsersScanner{
		bucketClient: bucketClient,
		logger:       logger,
		isOwned:      isOwned,
	}
}

// NewUsersScannerStrict creates a UsersScanner that skips a tenant when the
// ownership check returns an error (fail-closed). This matches the sibling
// compaction path (see Compactor.compactUsers) and is required for the
// destructive BlocksCleaner path, because every compactor replica observes
// the same ring state and a shared ring fault would otherwise cause every
// replica to simultaneously claim every tenant, violating the
// single-owner invariant for cleanup.
func NewUsersScannerStrict(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), logger log.Logger) *UsersScanner {
	return &UsersScanner{
		bucketClient:    bucketClient,
		logger:          logger,
		isOwned:         isOwned,
		strictOwnership: true,
	}
}

// ScanUsers returns a fresh list of users found in the storage, that are not marked for deletion,
// and list of users marked for deletion.
//
// If sharding is enabled, returned lists contains only the users owned by this instance.
func (s *UsersScanner) ScanUsers(ctx context.Context) (users, markedForDeletion []string, err error) {
	err = s.bucketClient.Iter(ctx, "", func(entry string) error {
		users = append(users, strings.TrimSuffix(entry, "/"))
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Check users for being owned by instance, and split users into non-deleted and deleted.
	// We do these checks after listing all users, to improve cacheability of Iter (result is only cached at the end of Iter call).
	for ix := 0; ix < len(users); {
		userID := users[ix]

		// Check if it's owned by this instance.
		owned, err := s.isOwned(userID)
		if err != nil {
			if s.strictOwnership {
				// Fail-closed: skip the tenant rather than assume ownership.
				// This is critical for destructive consumers (e.g. the blocks
				// cleaner) where fail-open would cause every replica to claim
				// every tenant on a shared ring fault.
				level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard; skipping", "user", userID, "err", err)
				users = append(users[:ix], users[ix+1:]...)
				continue
			}
			level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard", "user", userID, "err", err)
		} else if !owned {
			users = append(users[:ix], users[ix+1:]...)
			continue
		}

		deletionMarkExists, err := TenantDeletionMarkExists(ctx, s.bucketClient, userID)
		if err != nil {
			level.Warn(s.logger).Log("msg", "unable to check if user is marked for deletion", "user", userID, "err", err)
		} else if deletionMarkExists {
			users = append(users[:ix], users[ix+1:]...)
			markedForDeletion = append(markedForDeletion, userID)
			continue
		}

		ix++
	}

	return users, markedForDeletion, nil
}
