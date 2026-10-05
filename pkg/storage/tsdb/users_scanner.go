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
	// Both the ownership check and the deletion-mark check fail closed: if either returns an
	// error we drop the user from the returned list for this run. Callers (the compactor's
	// blocks cleaner in particular) rely on the ownership filter as a mutual-exclusion
	// guarantee -- a tenant must be processed by exactly one shard owner -- and the
	// destructive cleanup paths (block.Delete, bucketindex.WriteIndex/DeleteIndex) perform
	// unconditional overwrites with no lock or precondition. Keeping a tenant in the list
	// after an ownership error would let every replica concurrently run cleanUser /
	// deleteUserMarkedForDeletion for that tenant, producing lost bucket-index updates and
	// duplicate deletes. The sibling compaction loop in Compactor.compactUsers already fails
	// closed on the identical error; this matches that behavior. A skipped tenant is
	// retried on the next scan.
	for ix := 0; ix < len(users); {
		userID := users[ix]

		// Check if it's owned by this instance.
		owned, err := s.isOwned(userID)
		if err != nil {
			level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard, skipping", "user", userID, "err", err)
			users = append(users[:ix], users[ix+1:]...)
			continue
		} else if !owned {
			users = append(users[:ix], users[ix+1:]...)
			continue
		}

		deletionMarkExists, err := TenantDeletionMarkExists(ctx, s.bucketClient, userID)
		if err != nil {
			// Fail closed: if we cannot determine whether the tenant is marked for deletion we
			// must not hand it to cleanUser (which would run retention/partial-block deletion
			// for a tenant that may actually be in the deletion flow) nor to
			// deleteUserMarkedForDeletion. Skip the tenant for this run; it will be retried.
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
