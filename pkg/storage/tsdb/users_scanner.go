package tsdb

import (
	"context"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
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

	// tenantsSkipped, when set, is incremented every time a tenant is dropped from
	// the returned users list because the ownership check (isOwned) returned an
	// error. This lets operators observe cleanup being deferred to a subsequent
	// scan cycle when the ring/KV store is temporarily degraded.
	tenantsSkipped prometheus.Counter
}

func NewUsersScanner(bucketClient objstore.Bucket, isOwned func(userID string) (bool, error), logger log.Logger) *UsersScanner {
	return &UsersScanner{
		bucketClient: bucketClient,
		logger:       logger,
		isOwned:      isOwned,
	}
}

// SetOwnershipFailedCounter registers a counter that is incremented for every tenant whose
// ownership check fails and is consequently dropped from the returned users list. It is
// safe to pass nil to disable the counter, and safe to call before the scanner is used.
// This keeps the NewUsersScanner constructor signature stable for callers that do not
// need the metric (e.g. the querier bucket scan and the thanosconvert tool).
func (s *UsersScanner) SetOwnershipFailedCounter(c prometheus.Counter) {
	s.tenantsSkipped = c
}

// ScanUsers returns a fresh list of users found in the storage, that are not marked for deletion,
// and list of users marked for deletion.
//
// If sharding is enabled, returned lists contains only the users owned by this instance.
//
// When the ownership check (isOwned) returns an error for a tenant, the tenant is
// dropped from the returned users list (fail closed). The scanner is the single gate
// that decides which tenants a compactor is allowed to clean up and hard-delete blocks
// for, and cleanup is idempotent across cycles, so deferring a tenant whose ownership
// cannot be determined to the next scan cycle is strictly safer than letting every
// compactor replica consider itself the owner during a transient ring/KV fault.
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
			// Fail closed: drop the tenant from the returned list so that no instance
			// with a degraded ring view treats this tenant as owned. See the
			// "Cleanup should only be owned by a single compactor" invariant in
			// pkg/compactor/compactor.go. The next cleanup cycle will retry.
			level.Warn(s.logger).Log("msg", "unable to check if user is owned by this shard, skipping tenant for this cycle", "user", userID, "err", err)
			if s.tenantsSkipped != nil {
				s.tenantsSkipped.Inc()
			}
			users = append(users[:ix], users[ix+1:]...)
			continue
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
