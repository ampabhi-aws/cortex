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

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()

	t.Run("disabled by default", func(t *testing.T) {
		api := newTenantDeletionAPI(bkt, nil, Config{}, log.NewNopLogger())

		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", nil).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusNotFound, resp.Code)
		require.Empty(t, bkt.Objects())
	})

	cfg := Config{EnableTenantDeletionAPI: true}
	api := newTenantDeletionAPI(bkt, nil, cfg, log.NewNopLogger())

	t.Run("missing X-Scope-OrgID", func(t *testing.T) {
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", nil))
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("missing confirmation parameter", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", nil).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("mismatched confirmation parameter", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		form := strings.NewReader("tenant_id=other")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", form).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("matching confirmation parameter writes mark", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		form := strings.NewReader("tenant_id=fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", form).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	})

	t.Run("cancel delete tenant removes mark", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		form := strings.NewReader("tenant_id=fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", form).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.CancelDeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	})

	t.Run("cancel delete tenant is idempotent", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		form := strings.NewReader("tenant_id=fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", form).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.CancelDeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("cancel delete tenant disabled by default", func(t *testing.T) {
		api := newTenantDeletionAPI(bkt, nil, Config{}, log.NewNopLogger())
		ctx := user.InjectOrgID(context.Background(), "fake")
		form := strings.NewReader("tenant_id=fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/cancel_delete_tenant", form).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.CancelDeleteTenant(resp, req)
		require.Equal(t, http.StatusNotFound, resp.Code)
	})
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

			api := newTenantDeletionAPI(bkt, nil, Config{}, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
