package tenantfederation

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/tenant"
)

// TestNewQueryableWithMaxTenants verifies that the tenant federation
// MaxTenants limit is enforced before any per-tenant querier is allocated,
// and that a request exceeding the limit is rejected with HTTP 400.
func TestNewQueryableWithMaxTenants(t *testing.T) {
	tenant.WithDefaultResolver(tenant.NewMultiResolver())

	tests := []struct {
		name       string
		maxTenants int
		tenants    []string
		wantErr    bool
		wantCode   int32
	}{
		{name: "no limit", maxTenants: 0, tenants: []string{"a", "b", "c"}, wantErr: false},
		{name: "below limit", maxTenants: 3, tenants: []string{"a", "b"}, wantErr: false},
		{name: "at limit", maxTenants: 3, tenants: []string{"a", "b", "c"}, wantErr: false},
		{name: "above limit", maxTenants: 2, tenants: []string{"a", "b", "c"}, wantErr: true, wantCode: 400},
		{name: "single tenant with limit", maxTenants: 1, tenants: []string{"a"}, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &mockTenantQueryableWithFilter{}
			q := NewQueryableWithMaxTenants(upstream, tc.maxTenants, false /* byPassWithSingleQuerier */)

			ctx := user.InjectOrgID(context.Background(), strings.Join(tc.tenants, "|"))
			_, err := q.Querier(ctx, mint, maxt)
			if tc.wantErr {
				require.Error(t, err)
				resp, ok := httpgrpc.HTTPResponseFromError(err)
				require.True(t, ok, "expected httpgrpc error, got %T: %v", err, err)
				assert.Equal(t, tc.wantCode, resp.Code)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNewQueryableBackwardsCompat ensures the backwards-compatible
// NewQueryable constructor imposes no tenant-count limit.
func TestNewQueryableBackwardsCompat(t *testing.T) {
	tenant.WithDefaultResolver(tenant.NewMultiResolver())

	upstream := &mockTenantQueryableWithFilter{}
	q := NewQueryable(upstream, false)
	// a long tenant list must not be rejected when NewQueryable is used.
	ids := make([]string, 1024)
	for i := range ids {
		ids[i] = "t"
	}
	ctx := user.InjectOrgID(context.Background(), strings.Join(ids, "|"))
	_, err := q.Querier(ctx, mint, maxt)
	require.NoError(t, err)
}
