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

func newDeleteTenantRequest(t *testing.T, ctx context.Context, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "/purger/delete_tenant", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	return req
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	// No tenant in context -> 401.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	ctx := user.InjectOrgID(context.Background(), "fake")

	// Missing 'tenant' form parameter -> 400.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, ctx, url.Values{}))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// 'tenant' does not match authenticated tenant -> 403.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, ctx, url.Values{"tenant": {"other"}, "confirm": {"true"}}))
		require.Equal(t, http.StatusForbidden, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// Missing confirm -> 400.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, ctx, url.Values{"tenant": {"fake"}}))
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	// Correct form -> 200 and mark written.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, newDeleteTenantRequest(t, ctx, url.Values{"tenant": {"fake"}, "confirm": {"true"}}))
		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Undelete removes the mark.
	{
		req, err := http.NewRequest("POST", "/purger/undelete_tenant", strings.NewReader(url.Values{"tenant": {"fake"}}.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(ctx)
		resp := httptest.NewRecorder()
		api.UndeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		_, exists := objs[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, exists)
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
