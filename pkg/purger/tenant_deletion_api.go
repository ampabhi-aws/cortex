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

	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/alertmanager/alertstore"
	"github.com/cortexproject/cortex/pkg/ruler/rulestore"
	"github.com/cortexproject/cortex/pkg/storage/bucket"
	cortex_tsdb "github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
)

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	rulerStore   rulestore.RuleStore
	alertStore   alertstore.AlertStore
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
}

func NewTenantDeletionAPI(storageCfg cortex_tsdb.BlocksStorageConfig, rulerStore rulestore.RuleStore, alertStore alertstore.AlertStore, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPI(bucketClient, rulerStore, alertStore, cfgProvider, logger), nil
}

func newTenantDeletionAPI(bkt objstore.Bucket, rulerStore rulestore.RuleStore, alertStore alertstore.AlertStore, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		rulerStore:   rulerStore,
		alertStore:   alertStore,
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

	// 1. Mark the tenant's blocks for deletion in the blocks storage.
	if err := cortex_tsdb.WriteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now())); err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	// 2. Delete all rule groups for the tenant (if a ruler store is configured in this deployment).
	if api.rulerStore != nil {
		if err := api.rulerStore.DeleteNamespace(ctx, userID, "" /* all namespaces */); err != nil && !errors.Is(err, rulestore.ErrGroupNamespaceNotFound) {
			// Log and continue: the blocks mark is already written, and the status
			// endpoint will report rule_groups_deleted=false so automation and
			// operators can see that the ruler store still holds data (e.g. a
			// read-only backend such as local or configdb).
			level.Error(api.logger).Log("msg", "failed to delete tenant rule groups", "user", userID, "err", err)
		} else {
			level.Info(api.logger).Log("msg", "tenant rule groups deleted", "user", userID)
		}
	}

	// 3. Delete the tenant's Alertmanager configuration (if an alert store is configured in this deployment).
	if api.alertStore != nil {
		if err := api.alertStore.DeleteAlertConfig(ctx, userID); err != nil && !errors.Is(err, alertspb.ErrNotFound) {
			// Log and continue (see rationale above).
			level.Error(api.logger).Log("msg", "failed to delete tenant alertmanager config", "user", userID, "err", err)
		} else {
			level.Info(api.logger).Log("msg", "tenant alertmanager config deleted", "user", userID)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteTenantStatusResponse reports per-store deletion state for a tenant. A tenant
// is only fully deleted (as reported by the Deleted field) when every store Cortex
// is configured with has confirmed that no residual tenant objects remain.
type DeleteTenantStatusResponse struct {
	TenantID           string `json:"tenant_id"`
	BlocksDeleted      bool   `json:"blocks_deleted"`
	RuleGroupsDeleted  bool   `json:"rule_groups_deleted"`
	AlertConfigDeleted bool   `json:"alertmanager_config_deleted"`
	// Deleted is the overall verdict: true only when every configured per-store
	// check reports the tenant's data has been removed. Automation should wait
	// for this field rather than any single per-store boolean.
	Deleted bool `json:"deleted"`
}

func (api *TenantDeletionAPI) DeleteTenantStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := DeleteTenantStatusResponse{TenantID: userID}

	result.BlocksDeleted, err = api.isBlocksForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.RuleGroupsDeleted, err = api.areRuleGroupsForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.AlertConfigDeleted, err = api.isAlertConfigForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.Deleted = result.BlocksDeleted && result.RuleGroupsDeleted && result.AlertConfigDeleted

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

// areRuleGroupsForUserDeleted returns true when there are no remaining rule groups
// for the tenant, or when no ruler store is configured in this deployment (nothing
// to delete).
func (api *TenantDeletionAPI) areRuleGroupsForUserDeleted(ctx context.Context, userID string) (bool, error) {
	if api.rulerStore == nil {
		return true, nil
	}

	groups, err := api.rulerStore.ListRuleGroupsForUserAndNamespace(ctx, userID, "")
	if err != nil {
		if errors.Is(err, rulestore.ErrUserNotFound) || errors.Is(err, rulestore.ErrGroupNamespaceNotFound) {
			return true, nil
		}
		return false, err
	}
	return len(groups) == 0, nil
}

// isAlertConfigForUserDeleted returns true when the tenant has no Alertmanager
// configuration object, or when no alert store is configured in this deployment.
func (api *TenantDeletionAPI) isAlertConfigForUserDeleted(ctx context.Context, userID string) (bool, error) {
	if api.alertStore == nil {
		return true, nil
	}

	_, err := api.alertStore.GetAlertConfig(ctx, userID)
	if err != nil {
		if errors.Is(err, alertspb.ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func createBucketClient(cfg cortex_tsdb.BlocksStorageConfig, logger log.Logger, reg prometheus.Registerer) (objstore.Bucket, error) {
	bucketClient, err := bucket.NewClient(context.Background(), cfg.Bucket, "purger", logger, reg)
	if err != nil {
		return nil, errors.Wrap(err, "create bucket client")
	}

	return bucketClient, nil
}
