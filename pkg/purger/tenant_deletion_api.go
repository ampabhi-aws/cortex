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

	// Require an explicit confirmation parameter whose value matches the
	// tenant ID resolved from X-Scope-OrgID. This proves the caller intended
	// to destroy that specific tenant's data, and defeats CSRF (a cross-site
	// POST will not know the correct tenant string to supply).
	if err := requireTenantConfirmation(r, userID); err != nil {
		level.Warn(api.logger).Log("msg", "rejected tenant deletion request without matching confirmation parameter", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
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

// UndeleteTenant removes a previously written tenant deletion marker so that
// the compactor's blocks cleaner stops hard-deleting the tenant's blocks on
// subsequent cleanup cycles. Like DeleteTenant it is scoped to the caller's
// own X-Scope-OrgID and requires the matching confirmation parameter.
//
// Note: this reliably reverts an accidental or malicious delete_tenant call
// only if invoked before the next compactor cleanup cycle
// (-compactor.cleanup-interval, default 15m); any blocks the cleaner has
// already removed will not be restored.
func (api *TenantDeletionAPI) UndeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := requireTenantConfirmation(r, userID); err != nil {
		level.Warn(api.logger).Log("msg", "rejected tenant undeletion request without matching confirmation parameter", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.DeleteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider)
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to remove tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage removed", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// requireTenantConfirmation returns an error unless the request carries a
// `tenant` form or query parameter whose value equals userID. r.FormValue
// transparently reads from the URL query and, for POST, the
// application/x-www-form-urlencoded body.
func requireTenantConfirmation(r *http.Request, userID string) error {
	if v := r.FormValue("tenant"); v != "" {
		if v == userID {
			return nil
		}
		return errors.Errorf("confirmation parameter 'tenant' does not match X-Scope-OrgID")
	}
	return errors.Errorf("missing required confirmation parameter 'tenant'; it must equal the X-Scope-OrgID value")
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
