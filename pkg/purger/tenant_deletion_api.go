package purger

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/thanos-io/objstore"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	cortex_tsdb "github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
)

// maxDeleteTenantBodyBytes limits how much JSON the destructive endpoint will read.
const maxDeleteTenantBodyBytes = 1 << 10 // 1 KiB

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider

	// Audit metrics so the grace window is actionable from monitoring.
	deletionRequestedTotal *prometheus.CounterVec
	deletionCancelledTotal *prometheus.CounterVec
}

type deleteTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

func NewTenantDeletionAPI(storageCfg cortex_tsdb.BlocksStorageConfig, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPIWithRegistry(bucketClient, cfgProvider, logger, reg), nil
}

func newTenantDeletionAPI(bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *TenantDeletionAPI {
	return newTenantDeletionAPIWithRegistry(bkt, cfgProvider, logger, nil)
}

func newTenantDeletionAPIWithRegistry(bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		cfgProvider:  cfgProvider,
		logger:       logger,
		deletionRequestedTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_purger_tenant_deletion_requested_total",
			Help: "Total number of tenant deletion requests accepted by the purger, labelled by tenant.",
		}, []string{"user"}),
		deletionCancelledTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_purger_tenant_deletion_cancelled_total",
			Help: "Total number of tenant deletion requests cancelled during the grace period, labelled by tenant.",
		}, []string{"user"}),
	}
}

// DeleteTenant creates the tenant deletion marker in object storage. Because this
// is a maximally destructive, irreversible action, callers MUST send a JSON body
// echoing the tenant ID so that the request cannot be produced by a replay or by
// a cross-site simple form submission.
func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Require an explicit JSON confirmation whose tenant_id matches the X-Scope-OrgID.
	// This blocks cross-site simple-form POSTs (which cannot set Content-Type:application/json
	// without a CORS preflight) and accidental or replayed empty requests.
	if err := validateDeleteTenantConfirmation(r, userID); err != nil {
		level.Warn(api.logger).Log("msg", "rejecting tenant deletion request without valid confirmation", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.deletionRequestedTotal.WithLabelValues(userID).Inc()
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "user", userID)

	w.WriteHeader(http.StatusOK)
}

// validateDeleteTenantConfirmation enforces that the destructive request carries
// a JSON body echoing the tenant ID, matching the X-Scope-OrgID header.
func validateDeleteTenantConfirmation(r *http.Request, userID string) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return errors.New("missing Content-Type: application/json; the delete_tenant endpoint requires an explicit JSON confirmation body")
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return errors.Wrap(err, "invalid Content-Type")
	}
	if !strings.EqualFold(mediaType, "application/json") {
		return errors.Errorf("unsupported Content-Type %q: the delete_tenant endpoint requires application/json", mediaType)
	}

	if r.Body == nil {
		return errors.New("missing request body: expected JSON with tenant_id confirmation")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeleteTenantBodyBytes+1))
	if err != nil {
		return errors.Wrap(err, "failed to read request body")
	}
	if int64(len(body)) > maxDeleteTenantBodyBytes {
		return errors.New("request body too large")
	}
	if len(body) == 0 {
		return errors.New("empty request body: expected JSON with tenant_id confirmation")
	}

	var req deleteTenantRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return errors.Wrap(err, "failed to decode JSON body")
	}
	if req.TenantID == "" {
		return errors.New("request body must include tenant_id")
	}
	if req.TenantID != userID {
		return errors.Errorf("tenant_id %q in body does not match X-Scope-OrgID %q", req.TenantID, userID)
	}
	return nil
}

// CancelDeleteTenant removes a tenant deletion mark while the grace period is
// still running. It is a no-op (200) if no mark exists. If a FinishedTime is
// already set on the mark (i.e. the compactor has started/completed destructive
// cleanup), the cancellation is refused with 409 Conflict.
func (api *TenantDeletionAPI) CancelDeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	mark, err := cortex_tsdb.ReadTenantDeletionMark(ctx, api.bucketClient, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if mark == nil {
		// Nothing to cancel.
		w.WriteHeader(http.StatusOK)
		return
	}
	if mark.FinishedTime != 0 {
		http.Error(w, "tenant deletion already in progress; cannot cancel", http.StatusConflict)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.deletionCancelledTotal.WithLabelValues(userID).Inc()
	level.Info(api.logger).Log("msg", "tenant deletion cancelled", "user", userID)

	w.WriteHeader(http.StatusOK)
}

type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
	// DeletionTime is the Unix timestamp when the deletion mark was created, or 0 if no mark exists.
	DeletionTime int64 `json:"deletion_time,omitempty"`
	// FinishedTime is the Unix timestamp when the compactor finished block deletion for this tenant, or 0 if not finished.
	FinishedTime int64 `json:"finished_time,omitempty"`
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

	// Surface the mark lifecycle so callers know whether cancel is still possible.
	if mark, err := cortex_tsdb.ReadTenantDeletionMark(ctx, api.bucketClient, userID); err == nil && mark != nil {
		result.DeletionTime = mark.DeletionTime
		result.FinishedTime = mark.FinishedTime
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
