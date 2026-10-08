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

	// Apply the strict tenant-ID charset/length validation regardless of the
	// resolver mode. The default SingleResolver only rejects path-traversal
	// characters, which still allows arbitrary charsets (spaces, unicode,
	// control chars) to be used verbatim as object-storage prefixes. Writing
	// a tenant-deletion marker is a cluster-wide, bucket-polluting side
	// effect, so we require a well-formed tenant ID here.
	if err := tenant.ValidTenantID(userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userBucket := bucket.NewUserBucketClient(userID, api.bucketClient, api.cfgProvider)

	// Idempotency: if a deletion marker already exists for this tenant, do
	// not re-upload it. The marker is a fixed-path object inside the tenant
	// prefix, so re-upload is pure overhead and gives a trivial amplification
	// primitive for repeated POSTs.
	if exists, err := cortex_tsdb.TenantDeletionMarkExists(ctx, api.bucketClient, userID); err != nil {
		level.Error(api.logger).Log("msg", "failed to check tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if exists {
		level.Info(api.logger).Log("msg", "tenant deletion mark already exists, skipping re-upload", "user", userID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Refuse to create a marker (and therefore a brand new top-level bucket
	// prefix) for a tenant that has no data in the bucket. This prevents a
	// caller from creating phantom tenants that the compactor would then
	// re-scan every cleanup cycle.
	if empty, err := isUserPrefixEmpty(ctx, userBucket); err != nil {
		level.Error(api.logger).Log("msg", "failed to inspect tenant prefix", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if empty {
		http.Error(w, "no data for tenant", http.StatusNotFound)
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

// isUserPrefixEmpty returns true if the tenant's prefix in the bucket contains
// no objects at all. The caller must pass a bucket already scoped to the
// tenant (e.g. via bucket.NewUserBucketClient).
func isUserPrefixEmpty(ctx context.Context, userBkt objstore.Bucket) (bool, error) {
	var errNotEmpty = errors.New("not empty")
	err := userBkt.Iter(ctx, "", func(string) error {
		return errNotEmpty
	})
	if errors.Is(err, errNotEmpty) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
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
