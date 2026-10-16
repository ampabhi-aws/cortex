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
//
// Tenant deletion is destructive and irreversible: writing the deletion
// mark causes the compactor blocks cleaner to permanently remove every
// TSDB block of that tenant. Because Cortex has no built-in authorization
// layer and /purger/delete_tenant is served on the tenant-authenticated
// router, this handler enforces a defense-in-depth gate: the destructive
// path must be explicitly enabled by the operator, and admin invocations
// should name the target tenant in a request parameter rather than relying
// on the caller-supplied X-Scope-OrgID header.
type Config struct {
	// EnableTenantDeletion gates the destructive DeleteTenant handler. It
	// defaults to false so a holder of a tenant credential cannot delete
	// that tenant's blocks simply by POSTing to /purger/delete_tenant. Set
	// to true to re-enable the legacy self-service behaviour when running
	// behind a gateway known to restrict the /purger/ path.
	EnableTenantDeletion bool `yaml:"enable_tenant_deletion"`
}

// RegisterFlags registers configuration flags.
func (c *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&c.EnableTenantDeletion, "purger.enable-tenant-deletion", false,
		"Enable the POST /purger/delete_tenant endpoint. When false (default), the endpoint rejects "+
			"requests that would delete the caller's own tenant; an operator can still delete a named "+
			"tenant by passing an explicit 'tenant' request parameter, which should only be reachable "+
			"from an admin-scoped path. Deletion is destructive, so this flag must be enabled deliberately.")
}

type TenantDeletionAPI struct {
	bucketClient objstore.Bucket
	logger       log.Logger
	cfgProvider  bucket.TenantConfigProvider
	cfg          Config
}

func NewTenantDeletionAPI(cfg Config, storageCfg cortex_tsdb.BlocksStorageConfig, cfgProvider bucket.TenantConfigProvider, logger log.Logger, reg prometheus.Registerer) (*TenantDeletionAPI, error) {
	bucketClient, err := createBucketClient(storageCfg, logger, reg)
	if err != nil {
		return nil, err
	}

	return newTenantDeletionAPI(cfg, bucketClient, cfgProvider, logger), nil
}

func newTenantDeletionAPI(cfg Config, bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *TenantDeletionAPI {
	return &TenantDeletionAPI{
		bucketClient: bkt,
		cfgProvider:  cfgProvider,
		logger:       logger,
		cfg:          cfg,
	}
}

// resolveDeletionTarget determines which tenant should be deleted and the
// identity requesting the deletion. The principal is always read from the
// X-Scope-OrgID header (which Cortex assumes an upstream gateway has set).
// If the request carries an explicit "tenant" form value, that value is
// treated as an operator-supplied target and must be a valid tenant ID.
// Otherwise the target defaults to the principal and is subject to the
// EnableTenantDeletion opt-in.
func (api *TenantDeletionAPI) resolveDeletionTarget(r *http.Request) (principal, target string, adminTargeted bool, err error) {
	ctx := r.Context()
	principal, err = tenant.TenantID(ctx)
	if err != nil {
		return "", "", false, err
	}

	// Parse form values so query string and body form "tenant" are both honoured.
	// A parse error on the body is non-fatal; we still fall back to the principal.
	_ = r.ParseForm()
	explicit := strings.TrimSpace(r.FormValue("tenant"))
	if explicit == "" {
		return principal, principal, false, nil
	}

	if validateErr := tenant.ValidTenantID(explicit); validateErr != nil {
		return principal, "", true, validateErr
	}
	// Reject path-unsafe values the resolver would also reject.
	if explicit == "." || explicit == ".." || strings.ContainsAny(explicit, "/\\") {
		return principal, "", true, errors.New("invalid tenant parameter")
	}
	return principal, explicit, true, nil
}

func (api *TenantDeletionAPI) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	principal, targetID, adminTargeted, err := api.resolveDeletionTarget(r)
	if err != nil {
		// When Cortex is running, it uses Auth Middleware for checking X-Scope-OrgID and injecting tenant into context.
		// Auth Middleware sends http.StatusUnauthorized if X-Scope-OrgID is missing, so we do too here, for consistency.
		if principal == "" {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Gate: tenant deletion is destructive. Unless the operator explicitly
	// enables the endpoint via EnableTenantDeletion, only requests that name
	// an explicit target tenant (which an upstream admin-only path would
	// supply) are honoured. Self-deletion driven solely by the caller's
	// X-Scope-OrgID header is refused by default so a tenant credential
	// cannot destroy its own historical blocks.
	if !adminTargeted && !api.cfg.EnableTenantDeletion {
		level.Warn(api.logger).Log(
			"msg", "refusing tenant deletion: endpoint is disabled by default; set -purger.enable-tenant-deletion=true to allow self-deletion, or route through an admin path that supplies the 'tenant' parameter",
			"principal", principal,
			"target", targetID,
		)
		http.Error(w, "tenant deletion is disabled; set -purger.enable-tenant-deletion=true or invoke with an explicit 'tenant' parameter from an admin-authorised path", http.StatusForbidden)
		return
	}

	// WriteTenantDeletionMark keys the uploaded object on the targetID
	// argument (via NewUserBucketClient), so passing the original request
	// context is sufficient; the mark is written under the target tenant
	// prefix even when an operator is deleting a different tenant than the
	// caller principal.
	err = cortex_tsdb.WriteTenantDeletionMark(r.Context(), api.bucketClient, targetID, api.cfgProvider, cortex_tsdb.NewTenantDeletionMark(time.Now()))
	if err != nil {
		level.Error(api.logger).Log("msg", "failed to write tenant deletion mark", "principal", principal, "target", targetID, "admin_targeted", adminTargeted, "err", err)

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit log: capture the principal that requested deletion separately
	// from the tenant whose data is being destroyed.
	level.Info(api.logger).Log("msg", "tenant deletion mark in blocks storage created", "principal", principal, "target", targetID, "admin_targeted", adminTargeted)

	w.WriteHeader(http.StatusOK)
}

type DeleteTenantStatusResponse struct {
	TenantID      string `json:"tenant_id"`
	BlocksDeleted bool   `json:"blocks_deleted"`
}

func (api *TenantDeletionAPI) DeleteTenantStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, err := tenant.TenantID(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Honour the admin-targeted "tenant" parameter here too so operators can
	// check the status of a deletion they initiated for a different tenant.
	_ = r.ParseForm()
	targetID := principal
	if explicit := strings.TrimSpace(r.FormValue("tenant")); explicit != "" {
		if validateErr := tenant.ValidTenantID(explicit); validateErr != nil {
			http.Error(w, validateErr.Error(), http.StatusBadRequest)
			return
		}
		if explicit == "." || explicit == ".." || strings.ContainsAny(explicit, "/\\") {
			http.Error(w, "invalid tenant parameter", http.StatusBadRequest)
			return
		}
		targetID = explicit
	}

	result := DeleteTenantStatusResponse{}
	result.TenantID = targetID
	result.BlocksDeleted, err = api.isBlocksForUserDeleted(ctx, targetID)
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
