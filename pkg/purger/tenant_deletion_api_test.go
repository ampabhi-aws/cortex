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

	// Missing tenant in context -> Unauthorized.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Tenant in context but no confirmation parameter -> BadRequest, mark not written.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := httptest.NewRequest("POST", "/purger/delete_tenant", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		objs := bkt.Objects()
		require.Nil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Confirmation parameter does not match resolved tenant -> BadRequest.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := httptest.NewRequest("POST", "/purger/delete_tenant?tenant=other", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		objs := bkt.Objects()
		require.Nil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Matching confirmation parameter -> OK, mark written.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := httptest.NewRequest("POST", "/purger/delete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Matching confirmation via header also accepted.
	{
		bkt2 := objstore.NewInMemBucket()
		api2 := newTenantDeletionAPI(bkt2, nil, log.NewNopLogger())

		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := httptest.NewRequest("POST", "/purger/delete_tenant", nil)
		req.Header.Set("X-Cortex-Delete-Tenant-Confirm", "fake")
		resp := httptest.NewRecorder()
		api2.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt2.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}
}

func TestUndeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	ctx := context.Background()
	ctx = user.InjectOrgID(ctx, "fake")

	// First mark the tenant for deletion.
	{
		req := httptest.NewRequest("POST", "/purger/delete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Undelete without confirmation should be rejected.
	{
		req := httptest.NewRequest("POST", "/purger/undelete_tenant", nil)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Undelete with matching confirmation removes the mark.
	{
		req := httptest.NewRequest("POST", "/purger/undelete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		_, exists := bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, exists)
	}

	// Undeleting again when the mark is already gone is a no-op success.
	{
		req := httptest.NewRequest("POST", "/purger/undelete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
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
