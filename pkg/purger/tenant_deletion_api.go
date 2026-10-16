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

// Config holds configuration for the Purger service, in particular the
// administrative tenant-deletion endpoint. The tenant-deletion endpoint is
// strictly an administrative operation: it writes a marker that the compactor
// subsequently uses to hard-delete every block of a tenant from object storage,
// and causes ingesters to drop the tenant's TSDB. There is no in-process
// authorization check beyond the tenant-ID resolution performed by
// middleware.AuthenticateUser (which only copies the X-Scope-OrgID header into
// the request context). Operators must explicitly opt-in to registering the
// endpoint, and authenticating gateways must block it for tenant traffic.
// See docs/proposals/tenant-deletion.md.
type Config struct {
	// EnableAPI gates registration of the /purger/delete_tenant* endpoints.
	// It is OFF by default, mirroring the opt-in pattern used by the
	// experimental ruler and alertmanager APIs
	// (-experimental.ruler.enable-api, -experimental.alertmanager.enable-api).
	EnableAPI bool `yaml:"enable_api"`
}

// RegisterFlags registers flags for the Purger configuration.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableAPI, "experimental.purger.enable-api", false, "Enable the experimental, administrative tenant-deletion API (POST and DELETE /purger/delete_tenant, GET /purger/delete_tenant_status). This endpoint writes a marker that causes the compactor to permanently delete all of the tenant's blocks and ingesters to drop the tenant's local TSDB; it must not be exposed to tenants. Operators must additionally block /purger/* at the authenticating gateway.")
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

// DeleteTenant writes the tenant-deletion marker. It is an administrative
// operation: callers must repeat the tenant id in the confirm_tenant query
// parameter so that a stray or forged POST cannot trigger the destructive
// cleanup, and the caller is audit-logged.
func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Require an explicit confirmation parameter that matches the resolved
	// tenant id. This prevents a stray or forged POST (e.g. via CSRF/SSRF
	// through a gateway) from triggering an irreversible delete just by
	// reaching the URL with the correct X-Scope-OrgID header.
	confirm := r.URL.Query().Get("confirm_tenant")
	if confirm == "" {
		http.Error(w, "missing required query parameter: confirm_tenant must repeat the tenant id", http.StatusBadRequest)
		return
	}
	if confirm != userID {
		level.Warn(api.logger).Log("msg", "tenant deletion rejected: confirm_tenant does not match tenant id",
			"user", userID, "remote_addr", r.RemoteAddr, "user_agent", r.UserAgent())
		http.Error(w, "confirm_tenant does not match the tenant id in X-Scope-OrgID", http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit-log the destructive operation. Reverse proxies in front of Cortex
	// should also log and authenticate the caller; this provides a server-side
	// record even when the proxy log is unavailable.
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created",
		"user", userID, "remote_addr", r.RemoteAddr, "user_agent", r.UserAgent())

	w.WriteHeader(http.StatusOK)
}

// DeleteTenantDeletionMark removes a previously-written tenant-deletion marker,
// allowing an operator to cancel the destructive cleanup before the compactor
// has finished deleting the tenant's blocks. The call is idempotent: it
// succeeds even if no marker is present.
func (api *TenantDeletionAPI) DeleteTenantDeletionMark(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage removed",
		"user", userID, "remote_addr", r.RemoteAddr, "user_agent", r.UserAgent())

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
