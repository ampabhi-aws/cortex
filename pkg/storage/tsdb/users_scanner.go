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

// OnOwnershipErrorPolicy controls how UsersScanner.ScanUsers handles a transient error returned
// by the ownership callback. Different callers need different trade-offs:
//
//   - Destructive callers (e.g. the blocks cleaner) must fail closed and skip the tenant until the
//     owner can be determined, otherwise several replicas can concurrently run destructive work on
//     the same tenant prefix without any lock or conditional write and race each other.
//   - Non-destructive callers (e.g. the querier bucket scanner, offline tooling) can fail open and
//     keep processing the tenant so a transient ring/KV flap does not stall reads.
type OnOwnershipErrorPolicy int

const (
	// OnOwnershipErrorKeep keeps the tenant in the returned list when the ownership check errors.
	// This is the historical behaviour and should only be used by non-destructive callers that can
	// tolerate processing a tenant they do not own.
	OnOwnershipErrorKeep OnOwnershipErrorPolicy = iota

	// OnOwnershipErrorSkip removes the tenant from the returned list when the ownership check errors.
	// This fails closed and must be used by any destructive caller (e.g. the blocks cleaner) so that
	// transient ring instability cannot cause multiple replicas to concurrently delete the same
	// tenant's blocks or rewrite the bucket index.
	OnOwnershipErrorSkip
)

type UsersScanner struct {
	bucketClient   objstore.Bucket
	logger         log.Logger
	isOwned        func(userID string) (bool, error)
	onOwnershipErr OnOwnershipErrorPolicy
}

// NewUsersScanner returns a scanner that fails open on ownership errors (OnOwnershipErrorKeep).
// Use NewUsersScannerWithPolicy to override the error behaviour; destructive callers MUST pass
// OnOwnershipErrorSkip.
func NewUsersScanner(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), logger log.Logger) *UsersScanner {
	return NewUsersScannerWithPolicy(bucketClient, isOwned, OnOwnershipErrorKeep, logger)
}

// NewUsersScannerWithPolicy returns a scanner with an explicit ownership-error policy. Destructive
// callers (e.g. the compactor's blocks cleaner) should use OnOwnershipErrorSkip so that a transient
// ownership error cannot cause multiple replicas to simultaneously treat themselves as the single
// owner of the same tenant.
func NewUsersScannerWithPolicy(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), onOwnershipErr OnOwnershipErrorPolicy, logger log.Logger) *UsersScanner {
	return &UsersScanner{
		bucketClient:   bucketClient,
		logger:         logger,
		isOwned:        isOwned,
		onOwnershipErr: onOwnershipErr,
	}
}

// ScanUsers returns a fresh list of users found in the storage, that are not marked for deletion,
// and list of users marked for deletion.
//
// If sharding is enabled, returned lists contains only the users owned by this instance.
//
// When the ownership callback returns an error the scanner either keeps or skips the tenant based
// on the configured OnOwnershipErrorPolicy. Destructive consumers must use OnOwnershipErrorSkip so
// that transient ring errors do not cause several replicas to concurrently claim ownership of the
// same tenant.
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
			if s.onOwnershipErr == OnOwnershipErrorSkip {
				level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard, skipping user", "user", userID, "err", err)
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
