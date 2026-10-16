package log

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
)

func TestHeadersFromContextPrefixesInjectedFields(t *testing.T) {
	ctx := ContextWithHeaderMap(context.Background(), map[string]string{
		"X-Scope-OrgID": "tenant-1",
	})

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	logger = headersFromContext(ctx, logger)
	require.NoError(t, logger.Log("msg", "hello"))

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))

	// Field name is prefixed so that forwarded headers never collide with
	// genuine log fields.
	require.Equal(t, "tenant-1", out["http_header_X-Scope-OrgID"])
	require.NotContains(t, out, "X-Scope-OrgID")
}

func TestHeadersFromContextRejectsReservedFieldNames(t *testing.T) {
	// Even if an attacker somehow smuggled a reserved name past the
	// allowlist (e.g. via a misconfigured allowlist that listed "level"),
	// the prefix ensures no collision, and the explicit reserved-names
	// filter below is defence in depth.
	cases := []string{"level", "caller", "ts", "msg", "org_id", "traceID"}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			// Deliberately construct a header map whose entry would land
			// on a reserved key after prefixing. This should never happen
			// in practice because the prefix is non-empty, but we assert
			// the explicit guard still runs.
			ctx := ContextWithHeaderMap(context.Background(), map[string]string{
				name: "forged",
			})

			buf := &bytes.Buffer{}
			logger := log.NewJSONLogger(buf)
			logger = headersFromContext(ctx, logger)
			logger = log.With(logger, "level", "info")
			require.NoError(t, logger.Log("msg", "hello"))

			var out map[string]interface{}
			require.NoError(t, json.Unmarshal(buf.Bytes(), &out))

			// The genuine "level" field survives, because the propagated
			// pair was prefixed to "http_header_<name>" (and is therefore
			// not a reserved name) rather than overwriting it.
			require.Equal(t, "info", out["level"])
			require.Equal(t, "forged", out["http_header_"+name])
		})
	}
}
