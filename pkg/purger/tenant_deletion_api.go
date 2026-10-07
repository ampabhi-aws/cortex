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

// ConfirmDeleteHeader is the custom (non-simple) HTTP header a client must send,
// matching the tenant ID, to confirm an irreversible tenant deletion request.
// Requiring a non-simple header forces a CORS preflight for cross-origin callers,
// which blocks CSRF via <form> submissions since the browser cannot set this header
// without a successful preflight.
const ConfirmDeleteHeader = "X-Cortex-Confirm-Delete"

// ConfirmDeleteQueryParam is the URL query parameter a client must send,
// matching the tenant ID, to further confirm an irreversible tenant deletion request.
const ConfirmDeleteQueryParam = "confirm_tenant"

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Defence in depth against CSRF and accidental invocation of this
	// irreversible endpoint:
	//
	// 1. Reject form-encoded / simple cross-origin POSTs. A browser can only
	//    issue a CORS "simple" POST with Content-Type application/x-www-form-urlencoded,
	//    multipart/form-data or text/plain, so refusing anything that is not JSON
	//    blocks the classic <form action="..."> CSRF vector.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := ct
		if i := strings.IndexByte(mediaType, ';'); i >= 0 {
			mediaType = mediaType[:i]
		}
		mediaType = strings.TrimSpace(strings.ToLower(mediaType))
		if mediaType != "application/json" {
			api.auditDeleteAttempt(r, userID, "rejected: unsupported content-type")
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
	}

	// 2. Require a non-simple custom header whose value matches the tenant ID.
	//    Setting a custom header from a browser forces a CORS preflight the server
	//    will not approve (Cortex sets no CORS allowances), so this cannot be
	//    forged cross-origin.
	if r.Header.Get(ConfirmDeleteHeader) != userID {
		api.auditDeleteAttempt(r, userID, "rejected: missing or mismatched confirmation header")
		http.Error(w, "missing "+ConfirmDeleteHeader+" header matching the tenant ID", http.StatusBadRequest)
		return
	}

	// 3. Require an explicit confirmation query parameter echoing the tenant ID,
	//    so the caller cannot delete the wrong tenant by accident.
	if r.URL.Query().Get(ConfirmDeleteQueryParam) != userID {
		api.auditDeleteAttempt(r, userID, "rejected: missing or mismatched confirm_tenant query parameter")
		http.Error(w, ConfirmDeleteQueryParam+" query parameter must equal the tenant ID", http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID,
			"remote_addr", r.RemoteAddr,
			"forwarded_for", r.Header.Get("X-Forwarded-For"),
			"user_agent", r.Header.Get("User-Agent"),
			"origin", r.Header.Get("Origin"),
			"referer", r.Header.Get("Referer"),
			"err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit the full requester context, not just the tenant.
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID,
		"remote_addr", r.RemoteAddr,
		"forwarded_for", r.Header.Get("X-Forwarded-For"),
		"user_agent", r.Header.Get("User-Agent"),
		"origin", r.Header.Get("Origin"),
		"referer", r.Header.Get("Referer"))

	w.WriteHeader(http.StatusOK)
}

// auditDeleteAttempt logs a rejected tenant-deletion request with full requester
// context so operators have an audit trail of forged/accidental calls.
func (api *TenantDeletionAPI) auditDeleteAttempt(r *http.Request, userID, reason string) {
	level.Warn(api.logger).Log("msg", "tenant deletion request rejected", "user", userID, "reason", reason,
		"remote_addr", r.RemoteAddr,
		"forwarded_for", r.Header.Get("X-Forwarded-For"),
		"user_agent", r.Header.Get("User-Agent"),
		"origin", r.Header.Get("Origin"),
		"referer", r.Header.Get("Referer"))
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
