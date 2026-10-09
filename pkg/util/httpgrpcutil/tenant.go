package httpgrpcutil

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/user"
)

// ErrTenantMismatch is returned when the X-Scope-OrgID header inside an
// embedded httpgrpc request contradicts a separately asserted tenant ID.
// Treat it like an authentication/authorization failure.
var ErrTenantMismatch = errors.New("tenant mismatch between asserted UserID and X-Scope-OrgID header")

// EnforceTenantConsistency verifies that any X-Scope-OrgID header present in
// req matches the given tenantID, and otherwise injects it. The scheduler
// forwards request bodies verbatim to queriers, which later rebuild a real
// *http.Request from them; a divergence between the outer UserID and the
// inner header would mean two different tenants could be observed on the two
// sides of the hop, producing an unsafe tenant-identity primitive. This is a
// pure self-consistency check: it does not establish caller authenticity
// (that remains the responsibility of the external gateway and/or gRPC mTLS
// configured via -server.grpc-tls-*), but it prevents a caller from asserting
// a different tenant on the two paths that read tenant from the message.
//
// If req is nil the function is a no-op. If the header is absent it is
// injected from tenantID so downstream code sees a single, consistent value.
// If the header is present but does not match tenantID, ErrTenantMismatch is
// returned and req is left unchanged.
func EnforceTenantConsistency(req *httpgrpc.HTTPRequest, tenantID string) error {
	if req == nil {
		return nil
	}

	var found bool
	for _, h := range req.Headers {
		if !strings.EqualFold(h.Key, user.OrgIDHeaderName) {
			continue
		}
		for _, v := range h.Values {
			if v != tenantID {
				return errors.Wrapf(ErrTenantMismatch, "UserID=%q header=%q", tenantID, v)
			}
		}
		found = true
	}

	if !found {
		req.Headers = append(req.Headers, &httpgrpc.Header{
			Key:    user.OrgIDHeaderName,
			Values: []string{tenantID},
		})
	}
	return nil
}
