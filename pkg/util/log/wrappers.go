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

// HeadersFromContext enables the logging of specified HTTP Headers that have been added to a context
func headersFromContext(ctx context.Context, l log.Logger) log.Logger {
	headerContentsMap := HeaderMapFromContext(ctx)
	for header, contents := range headerContentsMap {
		// Sanitize the header name before using it as a log field key so
		// that a caller-supplied value can never produce an invalid key
		// (which would cause the logfmt encoder to drop the entire log
		// record). We replace any character that is not a valid HTTP
		// header-name token with '_' and fall back to a fixed name when
		// the entire key would otherwise be elided.
		sanitized := sanitizeLogFieldKey(header)
		l = kitlog.With(l, sanitized, contents)
	}
	return l
}

// sanitizeLogFieldKey returns a key that is safe to pass to go-kit's logfmt
// encoder: it is non-empty and contains only characters allowed in an HTTP
// header-name token (RFC 7230).
func sanitizeLogFieldKey(key string) string {
	if key == "" {
		return "http_header"
	}
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			b.WriteByte(c)
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	// A key composed exclusively of characters stripped by the logfmt
	// encoder (control chars, '=' or '"') would still reduce to the empty
	// string after that encoder's own filtering. Guard against that by
	// ensuring at least one alphanumeric character is present.
	hasToken := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			hasToken = true
			break
		}
	}
	if !hasToken {
		return "http_header"
	}
	return s
}
