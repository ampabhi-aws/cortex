package tenant

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/weaveworks/common/user"
)

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
	// maxTenants, when >0, bounds the number of tenant IDs a single request
	// may carry. Requests with more tenants are rejected before any fan-out.
	maxTenants int
}

// ErrTooManyTenants is returned when a federated request carries more tenant
// IDs than the configured maximum. The error is surfaced from MultiResolver
// to callers before any per-tenant work is scheduled.
var ErrTooManyTenants = errors.New("too many tenant IDs in request")

// NewMultiResolver creates a tenant resolver, which allows request to have
// multiple tenant ids submitted separated by a '|' character. This enforces
// further limits on the character set allowed within tenants as detailed here:
// https://cortexmetrics.io/docs/guides/limitations/#tenant-id-naming)
//
// The returned resolver imposes no upper bound on the number of tenant IDs in
// a single request. Use NewMultiResolverWithMaxTenants to bound fan-out and
// mitigate N-fold query amplification when tenant federation is enabled on an
// untrusted ingress.
func NewMultiResolver() *MultiResolver {
	return &MultiResolver{}
}

// NewMultiResolverWithMaxTenants creates a MultiResolver that rejects requests
// carrying more than maxTenants tenant IDs. A non-positive maxTenants disables
// the bound (equivalent to NewMultiResolver).
func NewMultiResolverWithMaxTenants(maxTenants int) *MultiResolver {
	return &MultiResolver{maxTenants: maxTenants}
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

	// Reject obviously oversized headers before splitting. We bound the raw
	// header to maxTenants * (per-tenant max length + separator) so the
	// X-Scope-OrgID header cannot be used as a memory amplifier to allocate a
	// multi-MiB string and a corresponding slice before validation.
	if t.maxTenants > 0 && len(orgID) > t.maxTenants*(maxTenantIDLength+1) {
		return nil, ErrTooManyTenants
	}

	orgIDs := strings.Split(orgID, tenantIDsLabelSeparator)
	// Enforce the fan-out bound before per-ID validation so an attacker cannot
	// force an O(N) validation pass over a huge tenant list.
	if t.maxTenants > 0 && len(orgIDs) > t.maxTenants {
		return nil, ErrTooManyTenants
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
