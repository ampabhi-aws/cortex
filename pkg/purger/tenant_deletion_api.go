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

// Config holds the configuration for the tenant deletion API.
type Config struct {
	// EnableTenantDeletionAPI opts the tenant deletion endpoints into the HTTP
	// router. It is disabled by default: the operation is irreversible for
	// already-deleted blocks and should only be reachable from an
	// operator-controlled surface.
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

// RegisterFlags registers tenant deletion API flags.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false,
		"Enable the tenant deletion API endpoints (/purger/delete_tenant, /purger/delete_tenant_status, /purger/undelete_tenant). The delete operation is irreversible for blocks already removed by the compactor and must not be exposed to tenant data-plane callers; operators who enable this flag are responsible for restricting /purger/* at their reverse proxy.")
}

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
		// When Cortex is running, it uses Auth Middleware for checking the
		// tenant header and injecting the tenant into the context. The Auth
		// Middleware sends http.StatusUnauthorized when the header is missing,
		// so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Require an explicit confirmation parameter identifying the tenant to
	// delete. This defeats a blind POST issued by a caller that only holds
	// the tenant's data-plane credential: it must additionally know the
	// tenant id and intentionally echo it back.
	if !tenantConfirmationMatches(r, userID) {
		http.Error(w, "missing or mismatched tenant confirmation: supply form value 'tenant' or header 'X-Cortex-Delete-Tenant-Confirm' matching the resolved tenant", http.StatusBadRequest)
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

// UndeleteTenant removes the tenant deletion mark for the caller's tenant,
// providing a cancellation window for operators who need to recover from an
// accidental DeleteTenant call. It is gated by the same opt-in flag and
// requires the same confirmation parameter as DeleteTenant. It only removes
// the mark; blocks already hard-deleted by the compactor remain gone.
func (api *TenantDeletionAPI) UndeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !tenantConfirmationMatches(r, userID) {
		http.Error(w, "missing or mismatched tenant confirmation: supply form value 'tenant' or header 'X-Cortex-Delete-Tenant-Confirm' matching the resolved tenant", http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.DeleteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider)
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark removed from blocks storage", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// tenantConfirmationMatches verifies the caller supplied a confirmation value
// equal to the resolved tenant. The confirmation can be supplied either as
// the "tenant" form value (query string or application/x-www-form-urlencoded
// body) or as the "X-Cortex-Delete-Tenant-Confirm" header.
func tenantConfirmationMatches(r *http.Request, userID string) bool {
	if v := strings.TrimSpace(r.Header.Get("X-Cortex-Delete-Tenant-Confirm")); v != "" {
		return v == userID
	}

	if v := strings.TrimSpace(r.FormValue("tenant")); v != "" {
		return v == userID
	}

	return false
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
