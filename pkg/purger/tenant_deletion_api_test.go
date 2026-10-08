package purger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/storage/tsdb"
)

func newDeleteTenantRequest(body, contentType string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	// No X-Scope-OrgID -> 401.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Missing Content-Type -> 400 (CSRF-safe: simple form POSTs cannot set JSON without preflight).
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest("", "")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	// Wrong Content-Type -> 400.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(`{"tenant_id":"fake"}`, "text/plain")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	// Empty JSON body -> 400.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest("", "application/json")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	// Mismatched tenant_id -> 400.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(`{"tenant_id":"other"}`, "application/json")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	// Valid request with matching JSON body -> 200 and marker written.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(`{"tenant_id":"fake"}`, "application/json")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}
}

func TestCancelDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	ctx := user.InjectOrgID(context.Background(), "fake")

	// Cancel with no mark -> 200 (no-op).
	{
		req := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", nil).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.CancelDeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
	}

	// Create a mark via the delete endpoint and cancel it.
	{
		delReq := newDeleteTenantRequest(`{"tenant_id":"fake"}`, "application/json").WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, delReq)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])

		cancelReq := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", nil).WithContext(ctx)
		cancelResp := httptest.NewRecorder()
		api.CancelDeleteTenant(cancelResp, cancelReq)
		require.Equal(t, http.StatusOK, cancelResp.Code)
		_, ok := bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, ok, "tenant deletion mark should be removed after cancel")
	}
}

func TestDeleteTenantStatus(t *testing.T) {
	const username = "user"

	for name, tc := range map[string]struct {
		objects               map[string][]byte
		expectedBlocksDeleted bool
	}{
		"empty": {
			objects:               nil,
			expectedBlocksDeleted: true,
		},

		"no user objects": {
			objects: map[string][]byte{
				"different-user/01EQK4QKFHVSZYVJ908Y7HH9E0/meta.json": []byte("data"),
			},
			expectedBlocksDeleted: true,
		},

		"non-block files": {
			objects: map[string][]byte{
				"user/deletion-mark.json": []byte("data"),
			},
			expectedBlocksDeleted: true,
		},

		"block files": {
			objects: map[string][]byte{
				"user/01EQK4QKFHVSZYVJ908Y7HH9E0/meta.json": []byte("data"),
			},
			expectedBlocksDeleted: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			bkt := objstore.NewInMemBucket()
			// "upload" objects
			for objName, data := range tc.objects {
				require.NoError(t, bkt.Upload(context.Background(), objName, bytes.NewReader(data)))
			}

			api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
