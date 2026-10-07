package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/weaveworks/common/user"
)

// defaultMaxTenantIDs is the default upper bound on how many tenant IDs may be
// present in a single federated request. It is used by MultiResolver when no
// override has been installed via SetMaxTenantIDs. The default is intentionally
// conservative: real deployments rarely federate across more than a handful of
// tenants, while an unbounded list enables single-request fan-out DoS
// (CWE-770) via the merge queryable.
const defaultMaxTenantIDs = 10

// maxTenantIDs holds the current cap on the number of tenant IDs permitted in
// a federated X-Scope-OrgID. A value of 0 disables the check (unbounded). Set
// via SetMaxTenantIDs during process startup from the tenant-federation
// config.
var maxTenantIDs int32 = defaultMaxTenantIDs

// SetMaxTenantIDs installs the maximum number of tenant IDs allowed in a
// single federated request. A non-positive value disables the limit
// (unbounded) and should only be used in tests or where an outer component is
// known to enforce an equivalent bound.
func SetMaxTenantIDs(n int) {
	if n < 0 {
		n = 0
	}
	atomic.StoreInt32(&maxTenantIDs, int32(n))
}

// MaxTenantIDs returns the current limit on tenant IDs per request (0 means
// unbounded).
func MaxTenantIDs() int {
	return int(atomic.LoadInt32(&maxTenantIDs))
}

var defaultResolver Resolver = NewSingleResolver()

// WithDefaultResolver updates the resolver used for the package methods.
func WithDefaultResolver(r Resolver) {
	defaultResolver = r
}

// TenantID returns exactly a single tenant ID from the context. It should be
// used when a certain endpoint should only support exactly a single
// tenant ID. It returns an error user.ErrNoOrgID if there is no tenant ID
// supplied or user.ErrTooManyOrgIDs if there are multiple tenant IDs present.
//
// ignore stutter warning
//
//nolint:revive
func TenantID(ctx context.Context) (string, error) {
	return defaultResolver.TenantID(ctx)
}

// TenantIDs returns all tenant IDs from the context. It should return
// normalized list of ordered and distinct tenant IDs (as produced by
// NormalizeTenantIDs).
//
// ignore stutter warning
//
//nolint:revive
func TenantIDs(ctx context.Context) ([]string, error) {
	return defaultResolver.TenantIDs(ctx)
}

type Resolver interface {
	// TenantID returns exactly a single tenant ID from the context. It should be
	// used when a certain endpoint should only support exactly a single
	// tenant ID. It returns an error user.ErrNoOrgID if there is no tenant ID
	// supplied or user.ErrTooManyOrgIDs if there are multiple tenant IDs present.
	TenantID(context.Context) (string, error)

	// TenantIDs returns all tenant IDs from the context. It should return
	// normalized list of ordered and distinct tenant IDs (as produced by
	// NormalizeTenantIDs).
	TenantIDs(context.Context) ([]string, error)
}

// NewSingleResolver creates a tenant resolver, which restricts all requests to
// be using a single tenant only. This allows a wider set of characters to be
// used within the tenant ID and should not impose a breaking change.
func NewSingleResolver() *SingleResolver {
	return &SingleResolver{}
}

type SingleResolver struct {
}

// containsUnsafePathSegments will return true if the string is a directory
// reference like `.` and `..` or if any path separator character like `/` and
// `\` can be found.
func containsUnsafePathSegments(id string) bool {
	// handle the relative reference to current and parent path.
	if id == "." || id == ".." {
		return true
	}

	return strings.ContainsAny(id, "\\/")
}

var errInvalidTenantID = errors.New("invalid tenant ID")

func (t *SingleResolver) TenantID(ctx context.Context) (string, error) {
	//lint:ignore faillint wrapper around upstream method
	id, err := user.ExtractOrgID(ctx)
	if err != nil {
		return "", err
	}

	if containsUnsafePathSegments(id) {
		return "", errInvalidTenantID
	}

	return id, nil
}

func (t *SingleResolver) TenantIDs(ctx context.Context) ([]string, error) {
	orgID, err := t.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	return []string{orgID}, err
}

type MultiResolver struct {
}

// NewMultiResolver creates a tenant resolver, which allows request to have
// multiple tenant ids submitted separated by a '|' character. This enforces
// further limits on the character set allowed within tenants as detailed here:
// https://cortexmetrics.io/docs/guides/limitations/#tenant-id-naming)
func NewMultiResolver() *MultiResolver {
	return &MultiResolver{}
}

func (t *MultiResolver) TenantID(ctx context.Context) (string, error) {
	orgIDs, err := t.TenantIDs(ctx)
	if err != nil {
		return "", err
	}

	if len(orgIDs) > 1 {
		return "", user.ErrTooManyOrgIDs
	}

	return orgIDs[0], nil
}

func (t *MultiResolver) TenantIDs(ctx context.Context) ([]string, error) {
	//lint:ignore faillint wrapper around upstream method
	orgID, err := user.ExtractOrgID(ctx)
	if err != nil {
		return nil, err
	}

	orgIDs := strings.Split(orgID, tenantIDsLabelSeparator)
	if maxN := MaxTenantIDs(); maxN > 0 && len(orgIDs) > maxN {
		return nil, fmt.Errorf("too many tenant IDs: %d (max %d)", len(orgIDs), maxN)
	}
	for _, orgID := range orgIDs {
		if err := ValidTenantID(orgID); err != nil {
			return nil, err
		}
		if containsUnsafePathSegments(orgID) {
			return nil, errInvalidTenantID
		}
	}

	return NormalizeTenantIDs(orgIDs), nil
}

// ExtractTenantIDFromHTTPRequest extracts a single TenantID through a given
// resolver directly from a HTTP request.
func ExtractTenantIDFromHTTPRequest(req *http.Request) (string, context.Context, error) {
	//lint:ignore faillint wrapper around upstream method
	_, ctx, err := user.ExtractOrgIDFromHTTPRequest(req)
	if err != nil {
		return "", nil, err
	}

	tenantID, err := defaultResolver.TenantID(ctx)
	if err != nil {
		return "", nil, err
	}

	return tenantID, ctx, nil
}
