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

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	resp := DeleteTenantResponse{
		TenantID: userID,
		Message:  "tenant deletion mark written to blocks storage; blocks will be deleted asynchronously by the compactor and ingesters will stop shipping blocks for this tenant",
		Warning:  tenantDeletionScopeWarning,
	}
	util.WriteJSONResponse(w, resp)
}

// tenantDeletionScopeWarning is returned by both DeleteTenant and
// DeleteTenantStatus so operators (and compliance workflows) are not misled
// into believing that /purger/delete_tenant deletes all tenant data. The
// endpoint only drives the blocks-storage deletion path; alertmanager
// configuration and ruler rule groups must be deleted via their own
// dedicated endpoints.
const tenantDeletionScopeWarning = "POST /purger/delete_tenant only requests deletion of blocks-storage data for the tenant. " +
	"Alertmanager configuration (which may contain plaintext credentials such as smtp_auth_password, api_key or webhook tokens) " +
	"must be deleted separately via POST /multitenant_alertmanager/delete_tenant_config. " +
	"Ruler rule groups must be deleted separately via POST /ruler/delete_tenant_config. " +
	"Ingester-local TSDB/WAL state for this tenant is only reclaimed when -blocks-storage.tsdb.close-idle-tsdb-timeout is set to a non-zero value. " +
	"The blocks_deleted field in /purger/delete_tenant_status reflects only the absence of ULID-named block prefixes in the blocks bucket " +
	"and does NOT imply that other data classes have been destroyed."

type DeleteTenantResponse struct {
	TenantID string `json:"tenant_id"`
	Message  string `json:"message"`
	Warning  string `json:"warning"`
}

type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
	// Warning explains that BlocksDeleted does not imply overall tenant
	// deletion: alertmanager configs, ruler rule groups and ingester-local
	// state are not considered here and must be deleted via their own
	// endpoints. See tenantDeletionScopeWarning for details.
	Warning string `json:"warning"`
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
	result.Warning = tenantDeletionScopeWarning
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
