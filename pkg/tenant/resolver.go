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

// containsUnsafePathSegments will return true if the string is empty, a
// directory reference like `.` and `..`, or if any path separator character
// like `/` and `\` can be found. An empty tenant ID is unsafe because
// filepath.Join(dir, "") == dir and prefix+"/"+"" collapses the per-tenant
// scope to the shared parent scope.
func containsUnsafePathSegments(id string) bool {
	// handle the empty tenant ID and relative references to current/parent path.
	if id == "" || id == "." || id == ".." {
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
	for _, orgID := range orgIDs {
		// Reject empty '|'-separated segments (e.g. header values such as
		// "|", "a|" and "|a"): ValidTenantID now returns an error for "",
		// but also check containsUnsafePathSegments explicitly as defence in
		// depth since both guard against path/prefix collapsing.
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
