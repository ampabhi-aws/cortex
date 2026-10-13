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

// Config holds the Purger (tenant deletion API) configuration.
//
// The tenant deletion API is an administrative operation that permanently
// destroys all stored blocks for a tenant. Because Cortex itself only
// authenticates callers via the tenant selector header (X-Scope-OrgID), the
// endpoint is disabled by default and must be explicitly opted into by the
// operator, who is then responsible for routing it on a non-tenant-facing
// listener (or otherwise gating it with administrative credentials).
type Config struct {
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false, "Enables the tenant deletion HTTP API (POST /purger/delete_tenant and POST /purger/cancel_delete_tenant). This is an administrative endpoint that permanently destroys a tenant's stored blocks. It is disabled by default and, when enabled, MUST only be exposed to operators (never to tenant-facing gateways).")
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

// Enabled reports whether the destructive tenant-deletion endpoints are enabled
// by configuration. The read-only status endpoint remains available regardless.
func (api *TenantDeletionAPI) Enabled() bool {
	return api.cfg.EnableTenantDeletionAPI
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !api.cfg.EnableTenantDeletionAPI {
		http.Error(w, "tenant deletion API is disabled; enable with -purger.enable-tenant-deletion-api on an operator-only listener", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Require the caller to echo the tenant ID being destroyed. This guards
	// against accidental invocation (e.g. a credential replayed with no body
	// against the wrong tenant) by forcing a per-call confirmation.
	if err := r.ParseForm(); err != nil {
		http.Error(w, errors.Wrap(err, "failed to parse request parameters").Error(), http.StatusBadRequest)
		return
	}
	confirm := r.Form.Get("tenant_id")
	if confirm == "" {
		http.Error(w, "missing required confirmation parameter 'tenant_id'; it must match the X-Scope-OrgID header", http.StatusBadRequest)
		return
	}
	if confirm != userID {
		http.Error(w, "confirmation parameter 'tenant_id' does not match the X-Scope-OrgID header", http.StatusBadRequest)
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

// CancelDeleteTenant removes an outstanding tenant-deletion mark. This gives
// operators a limited window to abort a mistakenly-issued deletion request
// before the compactor's blocks cleaner begins hard-deleting blocks.
func (api *TenantDeletionAPI) CancelDeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !api.cfg.EnableTenantDeletionAPI {
		http.Error(w, "tenant deletion API is disabled; enable with -purger.enable-tenant-deletion-api on an operator-only listener", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, errors.Wrap(err, "failed to parse request parameters").Error(), http.StatusBadRequest)
		return
	}
	confirm := r.Form.Get("tenant_id")
	if confirm == "" {
		http.Error(w, "missing required confirmation parameter 'tenant_id'; it must match the X-Scope-OrgID header", http.StatusBadRequest)
		return
	}
	if confirm != userID {
		http.Error(w, "confirmation parameter 'tenant_id' does not match the X-Scope-OrgID header", http.StatusBadRequest)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to remove tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark removed", "user", userID)
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
