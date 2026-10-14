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
}

func NewUsersScanner(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), logger log.Logger) *UsersScanner {
	return &UsersScanner{
		bucketClient: bucketClient,
		logger:       logger,
		isOwned:      isOwned,
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
	//
	// Both the ownership check and the tenant-deletion-mark check fail closed: if the check
	// returns an error we drop the user from the returned lists for this scan. This matches
	// the behaviour of the compaction path (see compactor.compactUsers) and prevents the
	// blocks cleaner from concurrently mutating shared per-tenant state (bucket index,
	// deletion markers) on every replica while e.g. the compactor ring/KV store is unstable.
	for ix := 0; ix < len(users); {
		userID := users[ix]

		// Check if it's owned by this instance. Treat a check error as "not owned" so we
		// never process a tenant whose ownership we could not verify.
		owned, err := s.isOwned(userID)
		if err != nil {
			level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard, skipping", "user", userID, "err", err)
			users = append(users[:ix], users[ix+1:]...)
			continue
		} else if !owned {
			users = append(users[:ix], users[ix+1:]...)
			continue
		}

		// Check if the tenant is marked for deletion. Treat a check error as "unknown state"
		// and skip the tenant so we never silently clean a tenant whose deletion state we
		// could not determine.
		deletionMarkExists, err := TenantDeletionMarkExists(ctx, s.bucketClient, userID)
		if err != nil {
			level.Warn(s.logger).Log("msg", "unable to check if user is marked for deletion, skipping", "user", userID, "err", err)
			users = append(users[:ix], users[ix+1:]...)
			continue
		} else if deletionMarkExists {
			users = append(users[:ix], users[ix+1:]...)
			markedForDeletion = append(markedForDeletion, userID)
			continue
		}

		ix++
	}

	return users, markedForDeletion, nil
}
