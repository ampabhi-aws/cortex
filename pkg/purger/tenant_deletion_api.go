package purger

import (
	"context"
	"flag"
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

// Config holds configuration for the tenant deletion API.
type Config struct {
	EnableTenantDeletionAPI bool          `yaml:"enable_tenant_deletion_api"`
	DeletionGracePeriod     time.Duration `yaml:"tenant_deletion_grace_period"`
}

// RegisterFlags registers CLI flags for the tenant deletion API.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false,
		"Enable the POST /purger/delete_tenant administrative endpoint. The endpoint is irreversible and should be exposed only on an admin-only listener.")
	f.DurationVar(&cfg.DeletionGracePeriod, "purger.tenant-deletion-grace-period", 24*time.Hour,
		"Minimum time between a tenant deletion mark being written and the compactor hard-deleting the tenant blocks. During this window POST /purger/cancel_delete_tenant can remove the mark.")
}

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
	cfg          Config
}

func NewTenantDeletionAPI(storageCfg cortex_tsdb.BlocksStorageConfig, cfgProvider bucket.TenantConfigProvider, cfg Config, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPI(bucketClient, cfgProvider, cfg, logger), nil
}

func newTenantDeletionAPI(bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, cfg Config, logger log.Logger) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		cfgProvider:  cfgProvider,
		cfg:          cfg,
		logger:       logger,
	}
}

func (api *TenantDeletionAPI) resolveTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID, err := tenant.TenantID(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", false
	}
	return userID, true
}

// checkConfirmation verifies that the tenant query parameter is present and
// matches the resolved tenant.
func checkConfirmation(r *http.Request, userID string) error {
	q := r.URL.Query().Get("tenant")
	if q == "" {
		return errors.New("missing required tenant confirmation query parameter; it must equal the tenant whose data is being deleted")
	}
	if q != userID {
		return errors.New("tenant confirmation query parameter does not match the authenticated tenant")
	}
	return nil
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !api.cfg.EnableTenantDeletionAPI {
		http.Error(w, "tenant deletion API is disabled; enable with -purger.enable-tenant-deletion-api", http.StatusForbidden)
		return
	}

	userID, ok := api.resolveTenant(w, r)
	if !ok {
		return
	}

	if err := checkConfirmation(r, userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID,
		"grace_period", api.cfg.DeletionGracePeriod.String())

	w.WriteHeader(http.StatusOK)
}

// CancelDeleteTenant removes the tenant deletion mark, aborting the pending
// deletion.
func (api *TenantDeletionAPI) CancelDeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !api.cfg.EnableTenantDeletionAPI {
		http.Error(w, "tenant deletion API is disabled; enable with -purger.enable-tenant-deletion-api", http.StatusForbidden)
		return
	}

	userID, ok := api.resolveTenant(w, r)
	if !ok {
		return
	}

	if err := checkConfirmation(r, userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	mark, err := cortex_tsdb.ReadTenantDeletionMark(ctx, api.bucketClient, userID)
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to read tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if mark == nil {
		http.Error(w, "no pending tenant deletion to cancel", http.StatusNotFound)
		return
	}
	if mark.FinishedTime != 0 {
		http.Error(w, "tenant deletion has already started; cancellation is no longer possible", http.StatusConflict)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark cancelled", "user", userID)
	w.WriteHeader(http.StatusOK)
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
			return nil
		}

		return errBlockFound
	})

	if errors.Is(err, errBlockFound) {
		return false, nil
	}

	if err != nil {
		return false, err
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
