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

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// This endpoint only triggers deletion of blocks-storage data for the
	// tenant. Ruler rule groups and Alertmanager configuration (which may
	// contain third-party notification credentials) are stored separately and
	// are NOT purged by this call. Operators must additionally invoke the
	// dedicated admin endpoints to delete that state:
	//   POST /ruler/delete_tenant_config
	//   POST /multitenant_alertmanager/delete_tenant_config
	level.Info(api.logger).Log(
		"msg", "tenant deletion mark in blocks storage created; this endpoint does NOT delete ruler rule groups or alertmanager configuration (including notification credentials); call /ruler/delete_tenant_config and /multitenant_alertmanager/delete_tenant_config separately to purge those stores",
		"user", userID,
	)

	w.WriteHeader(http.StatusOK)
}

// DeleteTenantStatusResponse is returned by the delete_tenant_status endpoint.
//
// Only the status of blocks-storage deletion is reported here. This endpoint
// does not inspect or report on ruler or alertmanager object storage. A
// "blocks_deleted": true response does NOT mean that the tenant's rule groups
// or Alertmanager configuration (which may contain notification credentials)
// have been removed; those must be deleted separately via
// POST /ruler/delete_tenant_config and
// POST /multitenant_alertmanager/delete_tenant_config.
type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
	// Scope is a human-readable description of what this status covers. It is
	// included to prevent callers from mistaking a "blocks_deleted: true"
	// response for complete tenant data erasure.
	Scope string `json:"scope"`
	// AdditionalCleanupRequired lists other admin endpoints that must be
	// invoked to fully erase tenant data from stores not covered by this API.
	AdditionalCleanupRequired []string `json:"additional_cleanup_required,omitempty"`
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
	result.Scope = "blocks-storage only; ruler and alertmanager configuration are not inspected by this endpoint"
	result.AdditionalCleanupRequired = []string{
		"POST /ruler/delete_tenant_config",
		"POST /multitenant_alertmanager/delete_tenant_config",
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
