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

// Config holds the config for the purger tenant-deletion HTTP API.
type Config struct {
	// EnableAPI gates registration of the destructive tenant-deletion HTTP
	// endpoints. It is disabled by default because the endpoints permanently
	// destroy a tenant's blocks and are intended for operator use only; the
	// deployment must opt in by setting this flag.
	EnableAPI bool `yaml:"enable_api"`
}

// RegisterFlags registers CLI flags.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableAPI, "purger.enable-api", false, "Enable the tenant-deletion HTTP API (POST and DELETE /purger/delete_tenant, GET /purger/delete_tenant_status). Disabled by default because the delete_tenant endpoint permanently destroys tenant data. Experimental.")
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

// DeleteTenant marks a tenant for deletion in blocks storage.
//
// To guard against unintended destructive invocations the caller must supply
// an explicit confirmation parameter ("tenant=<id>" via query string or form
// value) that matches the tenant resolved from the authenticated context.
// Every call is logged with the authenticated tenant and request origin so
// operators have an audit trail.
func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := requireTenantConfirmation(r, userID); err != nil {
		level.Warn(api.logger).Log("msg", "tenant deletion request rejected: missing or mismatched confirmation", "user", userID, "remote", r.RemoteAddr, "user_agent", r.UserAgent(), "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion requested", "user", userID, "remote", r.RemoteAddr, "user_agent", r.UserAgent())

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID, "remote", r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
}

// UndoDeleteTenant removes a previously written tenant deletion mark so that
// the compactor stops hard-deleting the tenant's blocks on its next cleanup
// cycle. It is the recoverable counterpart to DeleteTenant and requires the
// same confirmation parameter plus audit logging as the destructive call.
func (api *TenantDeletionAPI) UndoDeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := requireTenantConfirmation(r, userID); err != nil {
		level.Warn(api.logger).Log("msg", "undo tenant deletion request rejected: missing or mismatched confirmation", "user", userID, "remote", r.RemoteAddr, "user_agent", r.UserAgent(), "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	level.Info(api.logger).Log("msg", "undo tenant deletion requested", "user", userID, "remote", r.RemoteAddr, "user_agent", r.UserAgent())

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to remove tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark removed", "user", userID, "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

// requireTenantConfirmation enforces that the caller named the tenant being
// deleted in a "tenant" query/form parameter. This prevents destructive
// requests that merely rely on the X-Scope-OrgID header being set by another
// client (e.g. a browser or stale datasource) from succeeding.
func requireTenantConfirmation(r *http.Request, userID string) error {
	// ParseForm is cheap and populates r.Form from the query string and, for
	// POST/PUT requests, the application/x-www-form-urlencoded body. We treat
	// a parse failure as 'no confirmation supplied'.
	_ = r.ParseForm()
	confirm := r.Form.Get("tenant")
	if confirm == "" {
		return errors.New("missing required 'tenant' confirmation parameter: pass ?tenant=<tenant-id> matching the X-Scope-OrgID header")
	}
	if confirm != userID {
		return errors.New("'tenant' confirmation parameter does not match the X-Scope-OrgID tenant")
	}
	return nil
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
