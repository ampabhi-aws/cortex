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
	ruleStore    rulestore.RuleStore
	alertStore   alertstore.AlertStore
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
}

func NewTenantDeletionAPI(storageCfg cortex_tsdb.BlocksStorageConfig, ruleStore rulestore.RuleStore, alertStore alertstore.AlertStore, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPI(bucketClient, ruleStore, alertStore, cfgProvider, logger), nil
}

func newTenantDeletionAPI(bkt objstore.Bucket, ruleStore rulestore.RuleStore, alertStore alertstore.AlertStore, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		ruleStore:    ruleStore,
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

	// 1. Write the blocks-storage deletion mark. The compactor acts on this to reap
	// bucket index, blocks, debug/metas and the markers/ prefix for the tenant.
	err = cortex_tsdb.WriteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	// 2. Delete all rule groups for this tenant synchronously. The ruler store is
	// authoritative; deleting all namespaces removes rules/<tenant>/... from the
	// ruler bucket. Fail closed if the ruler store is not wired in so callers
	// cannot mistake a partial deletion for completion.
	if api.ruleStore == nil {
		level.Error(api.logger).Log("msg", "ruler storage not configured for tenant deletion", "user", userID)
		http.Error(w, "ruler storage not configured; tenant deletion is incomplete", http.StatusInternalServerError)
		return
	}
	if err := api.ruleStore.DeleteNamespace(ctx, userID, ""); err != nil && !errors.Is(err, rulestore.ErrGroupNamespaceNotFound) {
		level.Error(api.logger).Log("msg", "failed to delete tenant rule groups", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(api.logger).Log("msg", "tenant rule groups deleted", "user", userID)

	// 3. Delete the Alertmanager configuration and the replicated full state for
	// this tenant. The alertmanager config is the highest-secret-density per-tenant
	// object (webhook URLs, API tokens, SMTP credentials). Fail closed if the
	// alert store is not wired in.
	if api.alertStore == nil {
		level.Error(api.logger).Log("msg", "alertmanager storage not configured for tenant deletion", "user", userID)
		http.Error(w, "alertmanager storage not configured; tenant deletion is incomplete", http.StatusInternalServerError)
		return
	}
	if err := api.alertStore.DeleteAlertConfig(ctx, userID); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant alertmanager config", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := api.alertStore.DeleteFullState(ctx, userID); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant alertmanager full state", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(api.logger).Log("msg", "tenant alertmanager config and full state deleted", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// DeleteTenantStatusResponse reports completion of tenant deletion across every
// per-tenant store Cortex writes to. Complete is the AND of all per-store flags
// and is the only field callers should treat as "done".
type DeleteTenantStatusResponse struct {
	TenantID                  string `json:"tenant_id"`
	BlocksDeleted             bool   `json:"blocks_deleted"`
	RuleGroupsDeleted         bool   `json:"rule_groups_deleted"`
	AlertmanagerConfigDeleted bool   `json:"alertmanager_config_deleted"`
	// Complete is the AND of the per-store flags above. Callers must gate completion on this.
	Complete bool `json:"complete"`
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

	// Fail closed when a store is not wired in: we cannot confirm those stores are
	// clean, so we must not report Complete=true.
	result.RuleGroupsDeleted, err = api.areRuleGroupsForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.AlertmanagerConfigDeleted, err = api.isAlertmanagerConfigForUserDeleted(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.Complete = result.BlocksDeleted && result.RuleGroupsDeleted && result.AlertmanagerConfigDeleted

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

// areRuleGroupsForUserDeleted returns true iff the ruler store is wired in and
// holds no rule groups for the tenant. If the ruler store is not configured we
// cannot confirm deletion, so we fail closed by returning false.
func (api *TenantDeletionAPI) areRuleGroupsForUserDeleted(ctx context.Context, userID string) (bool, error) {
	if api.ruleStore == nil {
		return false, nil
	}
	groups, err := api.ruleStore.ListRuleGroupsForUserAndNamespace(ctx, userID, "")
	if err != nil {
		return false, err
	}
	return len(groups) == 0, nil
}

// isAlertmanagerConfigForUserDeleted returns true iff the alert store is wired
// in and holds neither a config nor a full-state object for the tenant. If the
// alert store is not configured we fail closed by returning false.
func (api *TenantDeletionAPI) isAlertmanagerConfigForUserDeleted(ctx context.Context, userID string) (bool, error) {
	if api.alertStore == nil {
		return false, nil
	}
	if _, err := api.alertStore.GetAlertConfig(ctx, userID); err != nil {
		if !errors.Is(err, alertspb.ErrNotFound) {
			return false, err
		}
	} else {
		return false, nil
	}
	if _, err := api.alertStore.GetFullState(ctx, userID); err != nil {
		if !errors.Is(err, alertspb.ErrNotFound) {
			return false, err
		}
	} else {
		return false, nil
	}
	return true, nil
}

func createBucketClient(cfg cortex_tsdb.BlocksStorageConfig, logger log.Logger, reg prometheus.Registerer) (objstore.Bucket, error) {
	bucketClient, err := bucket.NewClient(context.Background(), cfg.Bucket, "purger", logger, reg)
	if err != nil {
		return nil, errors.Wrap(err, "create bucket client")
	}

	return bucketClient, nil
}
