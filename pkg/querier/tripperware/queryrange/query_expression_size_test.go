package queryrange

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/user"
)

// TestValidateQueryExpressionSize exercises the byte-length guard that stops
// large PromQL expressions from reaching the recursive promql parser/printer.
func TestValidateQueryExpressionSize(t *testing.T) {
	t.Run("accepts small expressions", func(t *testing.T) {
		require.NoError(t, ValidateQueryExpressionSize("up"))
		require.NoError(t, ValidateQueryExpressionSize(strings.Repeat("a", MaxQueryExpressionSizeBytesDefault)))
	})

	t.Run("rejects oversized expressions with HTTP 400", func(t *testing.T) {
		oversized := strings.Repeat("(", MaxQueryExpressionSizeBytesDefault+1)
		err := ValidateQueryExpressionSize(oversized)
		require.Error(t, err)
		resp, ok := httpgrpc.HTTPResponseFromError(err)
		require.True(t, ok)
		require.Equal(t, int32(http.StatusBadRequest), resp.Code)
	})

	t.Run("limit can be disabled by setting <= 0", func(t *testing.T) {
		orig := MaxQueryExpressionSizeBytes
		t.Cleanup(func() { MaxQueryExpressionSizeBytes = orig })
		MaxQueryExpressionSizeBytes = 0
		require.NoError(t, ValidateQueryExpressionSize(strings.Repeat("(", 1<<20)))
	})
}

// TestDecodeRequestRejectsOversizedQuery ensures the codec rejects an
// oversized query form value before any downstream recursive parse.
func TestDecodeRequestRejectsOversizedQuery(t *testing.T) {
	oversized := strings.Repeat("(", MaxQueryExpressionSizeBytesDefault+1)

	form := url.Values{}
	form.Set("start", "0")
	form.Set("end", "60")
	form.Set("step", "60")
	form.Set("query", oversized)

	r, err := http.NewRequest(http.MethodPost, "/api/v1/query_range", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx := user.InjectOrgID(context.Background(), "1")
	r = r.Clone(ctx)

	_, err = PrometheusCodec.DecodeRequest(ctx, r, nil)
	require.Error(t, err)
	resp, ok := httpgrpc.HTTPResponseFromError(err)
	require.True(t, ok, "returned error is not an httpgrpc response")
	require.Equal(t, int32(http.StatusBadRequest), resp.Code)
}

// TestEvaluateAtModifierRejectsOversizedQuery is a defense-in-depth test for
// the split-by-interval middleware's call to evaluateAtModifierFunction.
func TestEvaluateAtModifierRejectsOversizedQuery(t *testing.T) {
	oversized := strings.Repeat("(", MaxQueryExpressionSizeBytesDefault+1)
	_, err := evaluateAtModifierFunction(oversized, 0, 60)
	require.Error(t, err)
	resp, ok := httpgrpc.HTTPResponseFromError(err)
	require.True(t, ok, "returned error is not an httpgrpc response")
	require.Equal(t, int32(http.StatusBadRequest), resp.Code)
}
