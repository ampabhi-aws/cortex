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

var defaultResolver Resolver = NewSingleResolver()

// defaultMaxTenantIDs is the default upper bound on the number of tenant IDs
// accepted in a single X-Scope-OrgID header. It is deliberately conservative
// to prevent query fan-out amplification (CWE-770) in multi-tenant query
// federation. Operators can tune this via tenantfederation.Config.MaxTenantIDs
// (which calls SetMaxTenantIDs below) when a different ceiling is required.
const defaultMaxTenantIDs = 16

// maxTenantIDs is the active ceiling, loaded atomically so that it can be
// updated once at startup from configuration without introducing locking on
// the hot path.
var maxTenantIDs int32 = defaultMaxTenantIDs

// SetMaxTenantIDs overrides the maximum number of tenant IDs accepted inside a
// single X-Scope-OrgID header. Values <= 0 reset the cap to the default. This
// is intended to be called at process startup from tenantfederation.Config.
func SetMaxTenantIDs(n int) {
	if n <= 0 {
		atomic.StoreInt32(&maxTenantIDs, defaultMaxTenantIDs)
		return
	}
	atomic.StoreInt32(&maxTenantIDs, int32(n))
}

// MaxTenantIDs returns the currently configured ceiling.
func MaxTenantIDs() int {
	return int(atomic.LoadInt32(&maxTenantIDs))
}

// maxTenantIDsHeaderBytes caps the raw length of the X-Scope-OrgID header
// before splitting on the separator. A single tenant ID is bounded to 150
// characters by ValidTenantID, so this budget covers the worst-case joined
// representation (plus a small slack for separators) and lets us reject
// pathological ~1 MB headers before the expensive split/sort.
func maxTenantIDsHeaderBytes() int {
	// 150 chars per ID + 1 separator per ID; include a small constant slack.
	return MaxTenantIDs()*(150+len(tenantIDsLabelSeparator)) + 16
}

var (
	errTooManyTenantIDs       = errors.New("too many tenant IDs in X-Scope-OrgID header")
	errTenantIDsHeaderTooLong = errors.New("X-Scope-OrgID header is too long")
)

// ErrTooManyTenantIDs is returned when the number of tenant IDs supplied in
// the X-Scope-OrgID header exceeds the configured cap. Exposed so callers can
// map it to an HTTP 400 response.
func ErrTooManyTenantIDs() error { return errTooManyTenantIDs }

// ErrTenantIDsHeaderTooLong is returned when the raw X-Scope-OrgID header is
// larger than the configured byte budget. Exposed for the same reason.
func ErrTenantIDsHeaderTooLong() error { return errTenantIDsHeaderTooLong }

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

	// Reject pathologically large headers before the expensive split/sort.
	// Each valid tenant ID is capped at 150 characters, so a legitimate
	// joined header stays well under this bound.
	if len(orgID) > maxTenantIDsHeaderBytes() {
		return nil, errTenantIDsHeaderTooLong
	}

	limit := MaxTenantIDs()
	// Fast path: cap the count before allocating a []string of unbounded size.
	// strings.Count(orgID, sep)+1 is the exact element count that Split would
	// produce, computed in O(n) without allocating.
	if strings.Count(orgID, tenantIDsLabelSeparator)+1 > limit {
		return nil, fmt.Errorf("%w: got more than %d tenant IDs", errTooManyTenantIDs, limit)
	}

	orgIDs := strings.Split(orgID, tenantIDsLabelSeparator)
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
