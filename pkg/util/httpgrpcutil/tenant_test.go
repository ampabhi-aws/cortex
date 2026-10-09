package httpgrpcutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/user"
)

func TestEnforceTenantConsistency(t *testing.T) {
	t.Run("nil request is a no-op", func(t *testing.T) {
		require.NoError(t, EnforceTenantConsistency(nil, "tenant-a"))
	})

	t.Run("absent header is injected", func(t *testing.T) {
		req := &httpgrpc.HTTPRequest{Method: "GET", Url: "/hello"}
		require.NoError(t, EnforceTenantConsistency(req, "tenant-a"))
		require.Len(t, req.Headers, 1)
		assert.Equal(t, user.OrgIDHeaderName, req.Headers[0].Key)
		assert.Equal(t, []string{"tenant-a"}, req.Headers[0].Values)
	})

	t.Run("matching header is accepted", func(t *testing.T) {
		req := &httpgrpc.HTTPRequest{
			Headers: []*httpgrpc.Header{
				{Key: user.OrgIDHeaderName, Values: []string{"tenant-a"}},
			},
		}
		require.NoError(t, EnforceTenantConsistency(req, "tenant-a"))
	})

	t.Run("header match is case-insensitive on key", func(t *testing.T) {
		req := &httpgrpc.HTTPRequest{
			Headers: []*httpgrpc.Header{
				{Key: "x-scope-orgid", Values: []string{"tenant-a"}},
			},
		}
		require.NoError(t, EnforceTenantConsistency(req, "tenant-a"))
		// no injection: still one header
		require.Len(t, req.Headers, 1)
	})

	t.Run("header mismatch is rejected", func(t *testing.T) {
		req := &httpgrpc.HTTPRequest{
			Headers: []*httpgrpc.Header{
				{Key: user.OrgIDHeaderName, Values: []string{"attacker"}},
			},
		}
		err := EnforceTenantConsistency(req, "victim")
		require.Error(t, err)
	})

	t.Run("any mismatched value in the list is rejected", func(t *testing.T) {
		req := &httpgrpc.HTTPRequest{
			Headers: []*httpgrpc.Header{
				{Key: user.OrgIDHeaderName, Values: []string{"tenant-a", "attacker"}},
			},
		}
		err := EnforceTenantConsistency(req, "tenant-a")
		require.Error(t, err)
	})
}
