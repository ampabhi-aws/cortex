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
	api := newTenantDeletionAPI(Config{EnableTenantDeletion: true}, bkt, nil, log.NewNopLogger())

	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// When the opt-in flag is false and the caller does not supply a 'tenant'
	// parameter, the handler must refuse to delete the caller's own tenant.
	{
		bkt := objstore.NewInMemBucket()
		disabled := newTenantDeletionAPI(Config{EnableTenantDeletion: false}, bkt, nil, log.NewNopLogger())

		ctx := user.InjectOrgID(context.Background(), "fake")
		req := &http.Request{}
		resp := httptest.NewRecorder()
		disabled.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusForbidden, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// With the opt-in flag disabled, an explicit 'tenant' parameter still
	// drives deletion of the named tenant (operator path through an
	// admin-scoped route).
	{
		bkt := objstore.NewInMemBucket()
		disabled := newTenantDeletionAPI(Config{EnableTenantDeletion: false}, bkt, nil, log.NewNopLogger())

		ctx := user.InjectOrgID(context.Background(), "admin-principal")
		req, err := http.NewRequestWithContext(ctx, "POST", "/purger/delete_tenant?tenant=target-tenant", nil)
		require.NoError(t, err)
		resp := httptest.NewRecorder()
		disabled.DeleteTenant(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("target-tenant", tsdb.TenantDeletionMarkPath)])
		require.Nil(t, objs[path.Join("admin-principal", tsdb.TenantDeletionMarkPath)])
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

			api := newTenantDeletionAPI(Config{}, bkt, nil, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
