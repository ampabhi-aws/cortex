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

	level.Info(api.logger).Log(
		"msg", "tenant deletion mark in blocks storage created",
		"user", userID,
		"note", "this endpoint only marks the blocks bucket; call POST /ruler/delete_tenant_config and POST /multitenant_alertmanager/delete_tenant_config to delete the tenant's rule groups and alertmanager configuration (which may embed notification credentials)",
	)

	w.WriteHeader(http.StatusOK)
}

// DeleteTenantStatusResponse is the JSON body returned by the tenant
// delete-status endpoint.
//
// NOTE: this endpoint only reflects the state of the *blocks* storage for a
// tenant. It does NOT examine the ruler store or the alertmanager store, and
// therefore does not report whether a tenant's rule groups or alertmanager
// configuration (which can embed notification credentials) have been removed.
// Those stores must be cleaned up via the dedicated endpoints:
//
//	POST /ruler/delete_tenant_config
//	POST /multitenant_alertmanager/delete_tenant_config
//
// The response therefore also includes `deletion_requested` (whether a
// blocks-storage tenant deletion mark currently exists) and
// `stores_not_covered`, which enumerates the per-tenant stores whose state is
// not reflected in this response, so operators cannot mistake it for full
// tenant erasure.
type DeleteTenantStatusResponse struct {
	TenantID string `json:"tenant_id"`
	// BlocksDeleted is true when no blocks remain under the tenant's prefix
	// in the blocks bucket. It only reflects blocks storage.
	BlocksDeleted bool `json:"blocks_deleted"`
	// DeletionRequested is true when a tenant-deletion mark exists in the
	// blocks bucket (i.e. POST /purger/delete_tenant has been called for
	// this tenant and the mark has not been cleaned up yet).
	DeletionRequested bool `json:"deletion_requested"`
	// StoresNotCovered enumerates per-tenant object stores whose state is
	// NOT reflected by this response. Operators must use the dedicated
	// endpoints for those stores to fully delete tenant data.
	StoresNotCovered []StoreNotCovered `json:"stores_not_covered"`
}

// StoreNotCovered describes a per-tenant object store whose deletion state is
// not reported by the purger tenant-deletion-status endpoint, together with
// the HTTP endpoint an operator should call to remove the tenant's data from
// that store.
type StoreNotCovered struct {
	Name        string `json:"name"`
	DeleteVia   string `json:"delete_via"`
	Description string `json:"description"`
}

// storesNotCoveredByBlocksDeletion lists the per-tenant object stores whose
// state the purger tenant-deletion endpoint does not touch. Keeping this list
// in one place lets both the log emitted by DeleteTenant and the status
// response share the same wording.
var storesNotCoveredByBlocksDeletion = []StoreNotCovered{
	{
		Name:        "ruler",
		DeleteVia:   "POST /ruler/delete_tenant_config",
		Description: "Per-tenant rule groups. Must be deleted separately; the purger tenant-deletion endpoint does not touch the ruler store.",
	},
	{
		Name:        "alertmanager",
		DeleteVia:   "POST /multitenant_alertmanager/delete_tenant_config",
		Description: "Per-tenant alertmanager configuration and templates (may embed notification credentials such as Slack/webhook URLs and SMTP passwords). Must be deleted separately; the purger tenant-deletion endpoint does not touch the alertmanager store.",
	},
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
	// Enumerate the per-tenant stores that this endpoint does NOT cover, so
	// operators cannot mistake a `blocks_deleted: true` response for full
	// tenant erasure.
	result.StoresNotCovered = append([]StoreNotCovered(nil), storesNotCoveredByBlocksDeletion...)

	result.DeletionRequested, err = cortex_tsdb.TenantDeletionMarkExists(ctx, api.bucketClient, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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
