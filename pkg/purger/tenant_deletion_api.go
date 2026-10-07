package purger

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/thanos-io/objstore"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	cortex_tsdb "github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
)

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
}

func NewTenantDeletionAPI(storageCfg cortex_tsdb.BlocksStorageConfig, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPI(bucketClient, cfgProvider, logger), nil
}

func newTenantDeletionAPI(bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		cfgProvider:  cfgProvider,
		logger:       logger,
	}
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Always validate the tenant ID with the strict charset/length rules
	// (same as MultiResolver) before using it as a storage prefix. The
	// default SingleResolver only rejects path-traversal segments, which is
	// not sufficient here because the handler will create a brand new
	// top-level prefix in the shared blocks bucket for any accepted value.
	// Without this, an attacker that can pick arbitrary X-Scope-OrgID values
	// can mint unbounded fake tenant prefixes and starve the compactor
	// cleanup loop (CWE-770).
	if err := tenant.ValidTenantID(userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Only accept the request if the tenant already has data in the bucket.
	// This prevents an attacker from using this endpoint to create arbitrary
	// new top-level prefixes that the compactor must then process every
	// cleanup cycle.
	hasData, err := api.tenantHasData(ctx, userID)
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to check tenant existence in bucket", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !hasData {
		http.Error(w, "unknown tenant", http.StatusNotFound)
		return
	}

	// Make the endpoint idempotent: if a deletion mark already exists do not
	// overwrite it, otherwise a repeated POST would reset finished_time to 0
	// and keep the prefix alive forever (the compactor's final cleanup only
	// runs after finished_time + tenant-cleanup-delay has elapsed).
	existing, err := cortex_tsdb.ReadTenantDeletionMark(ctx, api.bucketClient, userID)
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to read tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing != nil {
		level.Info(api.logger).Log("msg", "tenant deletion mark already exists, request is a no-op", "user", userID)
		w.WriteHeader(http.StatusOK)
		return
	}

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// tenantHasData reports whether the given tenant currently has any object in
// the blocks bucket. It is used to reject tenant-deletion requests for tenants
// whose prefix does not yet exist, so that the handler cannot be used to mint
// arbitrary new top-level prefixes.
func (api *TenantDeletionAPI) tenantHasData(ctx context.Context, userID string) (bool, error) {
	var errFound = errors.New("found")

	userBucket := bucket.NewUserBucketClient(userID, api.bucketClient, api.cfgProvider)
	err := userBucket.Iter(ctx, "", func(string) error {
		// Short-circuit: any single entry is enough to confirm the tenant exists.
		return errFound
	})
	if errors.Is(err, errFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
}

func (api *TenantDeletionAPI) DeleteTenantStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := DeleteTenantStatusResponse{}
	result.TenantID = userID
	result.BlocksDeleted, err = api.isBlocksForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	util.WriteJSONResponse(w, result)
}

func (api *TenantDeletionAPI) isBlocksForUserDeleted(ctx context.Context, userID string) (bool, error) {
	var errBlockFound = errors.New("block found")

	userBucket := bucket.NewUserBucketClient(userID, api.bucketClient, api.cfgProvider)
	err := userBucket.Iter(ctx, "", func(s string) error {
		s = strings.TrimSuffix(s, "/")

		_, err := ulid.Parse(s)
		if err != nil {
			// not block, keep looking
			return nil
		}

		// Used as shortcut to stop iteration.
		return errBlockFound
	})

	if errors.Is(err, errBlockFound) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	// No blocks found, all good.
	return true, nil
}

func createBucketClient(cfg cortex_tsdb.BlocksStorageConfig, logger log.Logger, reg prometheus.Registerer) (objstore.Bucket, error) {
	bucketClient, err := bucket.NewClient(context.Background(), cfg.Bucket, "purger", logger, reg)
	if err != nil {
		return nil, errors.Wrap(err, "create bucket client")
	}

	return bucketClient, nil
}
