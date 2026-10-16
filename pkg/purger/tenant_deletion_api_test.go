package purger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/storage/tsdb"
)

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	{
		// Missing confirm_tenant parameter must be rejected.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req, err := http.NewRequest("POST", "/purger/delete_tenant", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	{
		// Mismatched confirm_tenant must be rejected.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req, err := http.NewRequest("POST", "/purger/delete_tenant?confirm_tenant=other", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	{
		// Matching confirm_tenant writes the deletion marker.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req, err := http.NewRequest("POST", "/purger/delete_tenant?confirm_tenant=fake", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	{
		// DeleteTenantDeletionMark removes the marker (recovery path).
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req, err := http.NewRequest("DELETE", "/purger/delete_tenant", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		api.DeleteTenantDeletionMark(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		_, exists := objs[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, exists)
	}

	{
		// DeleteTenantDeletionMark is idempotent: removing an absent marker is OK.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req, err := http.NewRequest("DELETE", "/purger/delete_tenant", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		api.DeleteTenantDeletionMark(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
	}

	{
		// DeleteTenantDeletionMark requires a tenant id.
		resp := httptest.NewRecorder()
		api.DeleteTenantDeletionMark(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
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
