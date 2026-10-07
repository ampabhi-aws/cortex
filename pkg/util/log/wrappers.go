package log

import (
	"context"

	"github.com/go-kit/log"
	kitlog "github.com/go-kit/log"
	"github.com/weaveworks/common/tracing"

	"github.com/cortexproject/cortex/pkg/tenant"
)

// WithUserID returns a Logger that has information about the current user in
// its details.
func WithUserID(userID string, l kitlog.Logger) kitlog.Logger {
	// See note in WithContext.
	return kitlog.With(l, "org_id", userID)
}

// WithTraceID returns a Logger that has information about the traceID in
// its details.
func WithTraceID(traceID string, l kitlog.Logger) kitlog.Logger {
	// See note in WithContext.
	return kitlog.With(l, "traceID", traceID)
}

// WithContext returns a Logger that has information about the current user in
// its details.
//
// e.g.
//
//	log := util.WithContext(ctx)
//	log.Errorf("Could not chunk chunks: %v", err)
func WithContext(ctx context.Context, l kitlog.Logger) kitlog.Logger {
	l = headersFromContext(ctx, l)

	// Weaveworks uses "orgs" and "orgID" to represent Cortex users,
	// even though the code-base generally uses `userID` to refer to the same thing.
	userID, err := tenant.TenantID(ctx)
	if err == nil {
		l = WithUserID(userID, l)
	}

	traceID, ok := tracing.ExtractSampledTraceID(ctx)
	if !ok {
		return l
	}

	return WithTraceID(traceID, l)
}

// WithSourceIPs returns a Logger that has information about the source IPs in
// its details.
func WithSourceIPs(sourceIPs string, l log.Logger) log.Logger {
	return log.With(l, "sourceIPs", sourceIPs)
}

// loggedHeaderFieldPrefix is prepended to every header-derived structured
// log field so that the field names cannot collide with (and thereby
// shadow or spoof) first-class log keys such as `org_id`, `traceID`,
// `msg`, `level`, or `caller`. Combined with the allowlist on both the
// HTTP and gRPC ingress paths this ensures that nothing on the request
// surface can forge an otherwise-authoritative structured log field.
const loggedHeaderFieldPrefix = "http_header_"

// HeadersFromContext enables the logging of specified HTTP Headers that have been added to a context
func headersFromContext(ctx context.Context, l log.Logger) log.Logger {
	headerContentsMap := HeaderMapFromContext(ctx)
	for header, contents := range headerContentsMap {
		l = kitlog.With(l, loggedHeaderFieldPrefix+header, contents)
	}
	return l
}
