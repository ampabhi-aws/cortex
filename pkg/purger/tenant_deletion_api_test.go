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

func newDeleteTenantRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	t.Run("missing tenant header returns 401", func(t *testing.T) {
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(`{"confirm_tenant":"fake"}`)))
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("missing JSON content type is rejected", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodPost, "/purger/delete_tenant", strings.NewReader(`{"confirm_tenant":"fake"}`))
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusUnsupportedMediaType, resp.Code)
	})

	t.Run("empty body is rejected (CSRF resistant)", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(t, "")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("wrong confirm_tenant is rejected", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(t, `{"confirm_tenant":"other"}`)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	})

	t.Run("multiple X-Scope-OrgID headers are rejected", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(t, `{"confirm_tenant":"fake"}`)
		req.Header.Add("X-Scope-OrgID", "fake")
		req.Header.Add("X-Scope-OrgID", "other")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("valid confirmed request writes the mark", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := newDeleteTenantRequest(t, `{"confirm_tenant":"fake"}`)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	})

	t.Run("cancel removes the mark", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodDelete, "/purger/delete_tenant", strings.NewReader(`{"confirm_tenant":"fake"}`))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		api.CancelTenantDeletion(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	})

	t.Run("cancel without confirm_tenant is rejected", func(t *testing.T) {
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := httptest.NewRequest(http.MethodDelete, "/purger/delete_tenant", strings.NewReader(`{"confirm_tenant":"other"}`))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		api.CancelTenantDeletion(resp, req.WithContext(ctx))
		require.Equal(t, http.StatusBadRequest, resp.Code)
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

			api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
