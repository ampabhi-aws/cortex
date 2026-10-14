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
	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	cortex_tsdb "github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
)

type Config struct {
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false,
		"Enables the destructive tenant deletion API endpoint (POST /purger/delete_tenant). "+
			"This endpoint permanently deletes every TSDB block for the calling tenant, so it is disabled by default; "+
			"operators must set this flag only when the HTTP surface is restricted to trusted administrators.")
}

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
	sourceIPs    *middleware.SourceIPExtractor
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

func (api *TenantDeletionAPI) WithSourceIPExtractor(s *middleware.SourceIPExtractor) *TenantDeletionAPI {
	api.sourceIPs = s
	return api
}

func (api *TenantDeletionAPI) callerIdentity(r *http.Request) (sourceIP, userAgent string) {
	if api.sourceIPs != nil {
		sourceIP = api.sourceIPs.Get(r)
	}
	if sourceIP == "" {
		sourceIP = r.RemoteAddr
	}
	return sourceIP, r.UserAgent()
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sourceIP, userAgent := api.callerIdentity(r)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse request: "+err.Error(), http.StatusBadRequest)
		return
	}
	confirm := r.Form.Get("tenant_id")
	if confirm == "" {
		level.Warn(api.logger).Log("msg", "tenant deletion request rejected: missing confirmation parameter",
			"user", userID, "source_ip", sourceIP, "user_agent", userAgent)
		http.Error(w, "missing required 'tenant_id' confirmation parameter; it must equal the authenticated tenant", http.StatusBadRequest)
		return
	}
	if confirm != userID {
		level.Warn(api.logger).Log("msg", "tenant deletion request rejected: confirmation mismatch",
			"user", userID, "confirmation", confirm, "source_ip", sourceIP, "user_agent", userAgent)
		http.Error(w, "'tenant_id' confirmation parameter does not match the authenticated tenant", http.StatusBadRequest)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion requested",
		"user", userID, "source_ip", sourceIP, "user_agent", userAgent)

	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, userID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "user", userID, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created",
		"user", userID, "source_ip", sourceIP, "user_agent", userAgent)

	w.WriteHeader(http.StatusOK)
}

func (api *TenantDeletionAPI) CancelTenantDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sourceIP, userAgent := api.callerIdentity(r)

	mark, err := cortex_tsdb.ReadTenantDeletionMark(ctx, api.bucketClient, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if mark == nil {
		http.Error(w, "no pending tenant deletion to cancel", http.StatusNotFound)
		return
	}
	if mark.FinishedTime != 0 {
		level.Warn(api.logger).Log("msg", "refusing to cancel tenant deletion: cleanup already finished",
			"user", userID, "source_ip", sourceIP, "user_agent", userAgent)
		http.Error(w, "tenant deletion cleanup has already run; it cannot be cancelled", http.StatusConflict)
		return
	}

	if err := cortex_tsdb.DeleteTenantDeletionMark(ctx, api.bucketClient, userID, api.cfgProvider); err != nil {
		level.Error(api.logger).Log("msg", "failed to delete tenant deletion mark", "user", userID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(api.logger).Log("msg", "tenant deletion mark cancelled",
		"user", userID, "source_ip", sourceIP, "user_agent", userAgent)

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
