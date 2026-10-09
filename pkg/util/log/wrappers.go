package log

import (
	"context"
	"strings"

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

// reservedLogKeys are structured-log fields that must never be influenced by
// externally-controlled sources (HTTP headers / gRPC metadata forwarded for logging).
// We skip them in headersFromContext so that even if an operator mistakenly configures
// one of these names in `-api.http-request-headers-to-log`, a peer cannot forge the
// field's value.
var reservedLogKeys = map[string]struct{}{
	"level":     {},
	"ts":        {},
	"caller":    {},
	"msg":       {},
	"err":       {},
	"org_id":    {},
	"traceid":   {},
	"sourceips": {},
}

// HeadersFromContext enables the logging of specified HTTP Headers that have been added to a context
func headersFromContext(ctx context.Context, l log.Logger) log.Logger {
	headerContentsMap := HeaderMapFromContext(ctx)
	for header, contents := range headerContentsMap {
		if _, reserved := reservedLogKeys[strings.ToLower(header)]; reserved {
			// Skip reserved structured-log keys so a peer-supplied header named e.g.
			// `level` or `caller` cannot shadow the logger's own fields.
			continue
		}
		l = kitlog.With(l, header, contents)
	}
	return l
}
