package purger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/storage/tsdb"
)

func newDeleteTenantRequest(t *testing.T, orgID, confirm string) *http.Request {
	t.Helper()
	form := url.Values{}
	if confirm != "" {
		form.Set("tenant_id", confirm)
	}
	req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.Background()
	if orgID != "" {
		ctx = user.InjectOrgID(ctx, orgID)
	}
	return req.WithContext(ctx)
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	// No tenant header -> unauthorized.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", nil))
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Missing confirmation parameter -> bad request, nothing written.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, "fake", ""))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Confirmation mismatch -> bad request, nothing written.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, "fake", "other-tenant"))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Matching confirmation -> success, mark written.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, "fake", "fake"))
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}
}

func TestCancelTenantDeletion(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	// No mark -> 404.
	{
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", nil)
		req = req.WithContext(user.InjectOrgID(context.Background(), "fake"))
		api.CancelTenantDeletion(resp, req)
		require.Equal(t, http.StatusNotFound, resp.Code)
	}

	// Create a mark via DeleteTenant then cancel it.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, "fake", "fake"))
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])

		cancelResp := httptest.NewRecorder()
		cancelReq := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", nil)
		cancelReq = cancelReq.WithContext(user.InjectOrgID(context.Background(), "fake"))
		api.CancelTenantDeletion(cancelResp, cancelReq)
		require.Equal(t, http.StatusOK, cancelResp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
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
