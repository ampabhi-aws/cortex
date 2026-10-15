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

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Authenticated but no confirmation parameter -> 400.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// Authenticated with wrong confirmation parameter -> 400.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant?tenant=other", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// Authenticated with matching confirmation parameter (query) -> 200.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Authenticated with matching confirmation in form body -> 200.
	{
		bkt2 := objstore.NewInMemBucket()
		api2 := newTenantDeletionAPI(bkt2, nil, log.NewNopLogger())
		form := url.Values{"tenant": {"fake"}}
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

	// Write a mark first (via the delete endpoint, with confirmation).
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Missing X-Scope-OrgID -> 401.
	{
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, httptest.NewRequest(http.MethodPost, "/purger/undelete_tenant", nil))
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Missing confirmation parameter -> 400 and mark untouched.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/undelete_tenant", nil)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Matching confirmation -> 200 and marker removed.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/undelete_tenant?tenant=fake", nil)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		_, ok := bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, ok, "tenant deletion mark should have been removed")
	}

	// Idempotent: calling again when the marker is already gone still returns 200.
	{
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/undelete_tenant?tenant=fake", nil)
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
