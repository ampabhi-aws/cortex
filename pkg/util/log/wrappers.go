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

// forwardedHeaderFieldPrefix is prepended to every log field produced from a
// forwarded HTTP header so that propagated names can never collide with
// genuine log fields emitted by Cortex itself.
const forwardedHeaderFieldPrefix = "http_header_"

// reservedLogFieldNames are field names that must never be produced from a
// forwarded header, because they are used by the logging stack itself and
// overwriting them would corrupt structured-log output (particularly with
// -log.format=json, where the vendored go-kit JSON logger merges duplicate
// keys and the later value wins).
var reservedLogFieldNames = map[string]struct{}{
	"level":   {},
	"caller":  {},
	"ts":      {},
	"msg":     {},
	"org_id":  {},
	"traceID": {},
}

// HeadersFromContext enables the logging of specified HTTP Headers that have been added to a context
func headersFromContext(ctx context.Context, l log.Logger) log.Logger {
	headerContentsMap := HeaderMapFromContext(ctx)
	for header, contents := range headerContentsMap {
		field := forwardedHeaderFieldPrefix + header
		// Defence in depth: even with the prefix in place, refuse to emit
		// anything whose final field name collides with a reserved key.
		// The prefix makes this effectively unreachable, but the explicit
		// check guards against future changes to either the prefix or the
		// reserved-names list.
		if _, reserved := reservedLogFieldNames[strings.ToLower(field)]; reserved {
			continue
		}
		l = kitlog.With(l, field, contents)
	}
	return l
}
