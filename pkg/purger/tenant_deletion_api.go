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

	// Require the destructive operation to name its target tenant explicitly
	// and to carry a confirmation parameter, so that neither an empty POST
	// (which only carries X-Scope-OrgID) nor a stray/misrouted request can
	// trigger irreversible deletion.
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	targetTenant := r.Form.Get("tenant")
	if targetTenant == "" {
		http.Error(w, "missing required 'tenant' parameter", http.StatusBadRequest)
		return
	}
	if err := tenant.ValidTenantID(targetTenant); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The caller must explicitly name the tenant their credentials grant
	// access to; the API does not implicitly derive the target from the
	// auth header. Operators that firewall this endpoint and set the
	// X-Scope-OrgID header on behalf of their admin can delete any tenant
	// by naming it here.
	if targetTenant != userID {
		http.Error(w, "'tenant' parameter does not match authenticated tenant", http.StatusForbidden)
		return
	}
	if r.Form.Get("confirm") != "true" {
		http.Error(w, "missing or invalid 'confirm' parameter; set confirm=true to proceed", http.StatusBadRequest)
		return
	}

	source := requestSource(r)
	level.Warn(api.logger).Log(
		"msg", "tenant deletion requested",
		"user", targetTenant,
		"caller", userID,
		"source_ip", source,
		"user_agent", r.UserAgent(),
	)

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, targetTenant, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", targetTenant, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log(
		"msg", "tenant deletion mark in blocks storage created",
		"user", targetTenant,
		"caller", userID,
		"source_ip", source,
	)

	w.WriteHeader(http.StatusOK)
}

// UndeleteTenant removes a tenant deletion mark from blocks storage. If this
// is called before the compactor runs its cleanup pass, the tenant's blocks
// are not deleted and the deletion is effectively undone.
func (api *TenantDeletionAPI) UndeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	targetTenant := r.Form.Get("tenant")
	if targetTenant == "" {
		http.Error(w, "missing required 'tenant' parameter", http.StatusBadRequest)
		return
	}
	if err := tenant.ValidTenantID(targetTenant); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if targetTenant != userID {
		http.Error(w, "'tenant' parameter does not match authenticated tenant", http.StatusForbidden)
		return
	}

	source := requestSource(r)
	level.Warn(api.logger).Log(
		"msg", "tenant deletion rescind requested",
		"user", targetTenant,
		"caller", userID,
		"source_ip", source,
		"user_agent", r.UserAgent(),
	)

	if err := cortex_tsdb.DeleteTenantDeletionMark(r.Context(), api.bucketClient, targetTenant, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to remove tenant deletion mark", "user", targetTenant, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log(
		"msg", "tenant deletion mark removed from blocks storage",
		"user", targetTenant,
		"caller", userID,
		"source_ip", source,
	)

	w.WriteHeader(http.StatusOK)
}

// requestSource returns a best-effort source identifier for audit logging.
func requestSource(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return r.RemoteAddr
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
