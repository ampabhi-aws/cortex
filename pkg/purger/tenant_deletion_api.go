package purger

import (
	"context"
	"encoding/json"
	"io"
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

// orgIDHeader is the tenant selector header. It is defined in weaveworks/common/user
// but reproduced here to keep the audit/validation code free of that import.
const orgIDHeader = "X-Scope-OrgID"

// deleteTenantMaxBodyBytes bounds how much of the request body we will decode
// when looking for the confirmation token.
const deleteTenantMaxBodyBytes = 4096

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

// deleteTenantConfirmRequest is the (JSON) body that callers must submit to
// authorise destruction of their tenant data.
type deleteTenantConfirmRequest struct {
	ConfirmTenant string `json:"confirm_tenant"`
}

// rejectAmbiguousTenantHeader returns true (and writes the error response) when
// the request carries more than one X-Scope-OrgID header value. A compliant
// authentication proxy MUST strip any client-supplied value and then set
// exactly one tenant header; multiple values indicate either a misconfigured
// gateway (header appended rather than replaced) or an attempt by one tenant
// to assert another tenant's identity. Fail closed rather than silently
// picking the first value.
func rejectAmbiguousTenantHeader(w http.ResponseWriter, r *http.Request) bool {
	if len(r.Header.Values(orgIDHeader)) > 1 {
		http.Error(w, "multiple X-Scope-OrgID headers are not permitted", http.StatusBadRequest)
		return true
	}
	return false
}

// auditTenantDeletion emits a dedicated structured log record for every
// deletion attempt so operators can trace who destroyed what and from where.
func (api *TenantDeletionAPI) auditTenantDeletion(r *http.Request, userID, action, outcome string) {
	level.Warn(api.logger).Log(
		"msg", "tenant deletion API audit",
		"action", action,
		"outcome", outcome,
		"user", userID,
		"source_ip", r.RemoteAddr,
		"forwarded_for", r.Header.Get("X-Forwarded-For"),
		"user_agent", r.Header.Get("User-Agent"),
		"method", r.Method,
		"path", r.URL.Path,
		"time", time.Now().UTC().Format(time.RFC3339Nano),
	)
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if rejectAmbiguousTenantHeader(w, r) {
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

	// Require an explicit JSON body carrying a confirmation token equal to the
	// tenant being deleted. This defeats:
	//   * header-only one-liner replays (`curl -X POST .../delete_tenant`)
	//   * CSRF via a browser form POST (would be url-encoded, not JSON, and
	//     cannot forge a cross-site request with a non-simple Content-Type
	//     without triggering a CORS preflight the server never approves)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		api.auditTenantDeletion(r, userID, "delete", "rejected_content_type")
		http.Error(w, "Content-Type: application/json is required", http.StatusUnsupportedMediaType)
		return
	}

	var body deleteTenantConfirmRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, deleteTenantMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.ConfirmTenant != userID {
		api.auditTenantDeletion(r, userID, "delete", "rejected_confirmation")
		http.Error(w, "request body must be {\"confirm_tenant\":\"<X-Scope-OrgID being deleted>\"}", http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)
		api.auditTenantDeletion(r, userID, "delete", "storage_error")

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.auditTenantDeletion(r, userID, "delete", "accepted")
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// CancelTenantDeletion removes the tenant deletion mark for the calling
// tenant, aborting the pending destructive cleanup provided that the compactor
// has not yet begun deleting blocks. The caller must prove intent by sending
// an application/json body with {"confirm_tenant":"<tenant-id>"} just like
// the destructive endpoint.
func (api *TenantDeletionAPI) CancelTenantDeletion(w http.ResponseWriter, r *http.Request) {
	if rejectAmbiguousTenantHeader(w, r) {
		return
	}

	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		api.auditTenantDeletion(r, userID, "cancel", "rejected_content_type")
		http.Error(w, "Content-Type: application/json is required", http.StatusUnsupportedMediaType)
		return
	}

	var body deleteTenantConfirmRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, deleteTenantMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.ConfirmTenant != userID {
		api.auditTenantDeletion(r, userID, "cancel", "rejected_confirmation")
		http.Error(w, "request body must be {\"confirm_tenant\":\"<X-Scope-OrgID being cancelled>\"}", http.StatusBadRequest)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)
		api.auditTenantDeletion(r, userID, "cancel", "storage_error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.auditTenantDeletion(r, userID, "cancel", "accepted")
	level.Info(api.logger).Log("msg", "tenant deletion mark removed", "user", userID)

	w.WriteHeader(http.StatusOK)
}

type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
}

func (api *TenantDeletionAPI) DeleteTenantStatus(w http.ResponseWriter, r *http.Request) {
	if rejectAmbiguousTenantHeader(w, r) {
		return
	}
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
