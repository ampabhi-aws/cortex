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

	newRequest := func(ctx context.Context) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://cortex/purger/delete_tenant?confirm_tenant=fake", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Cortex-Confirm-Delete", "fake")
		if ctx != nil {
			req = req.WithContext(ctx)
		}
		return req
	}

	{
		// Missing tenant -> unauthorized.
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	ctx := user.InjectOrgID(context.Background(), "fake")

	{
		// Wrong content-type is rejected (CSRF defence against form posts).
		req := newRequest(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusUnsupportedMediaType, resp.Code)
	}

	{
		// Missing confirmation header is rejected.
		req := newRequest(ctx)
		req.Header.Del("X-Cortex-Confirm-Delete")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Mismatched confirmation header is rejected.
		req := newRequest(ctx)
		req.Header.Set("X-Cortex-Confirm-Delete", "other-tenant")
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Missing confirm_tenant query parameter is rejected.
		req := httptest.NewRequest(http.MethodPost, "http://cortex/purger/delete_tenant", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Cortex-Confirm-Delete", "fake")
		req = req.WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Mismatched confirm_tenant query parameter is rejected.
		req := httptest.NewRequest(http.MethodPost, "http://cortex/purger/delete_tenant?confirm_tenant=other", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Cortex-Confirm-Delete", "fake")
		req = req.WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Valid request with all confirmations succeeds and writes the mark.
		req := newRequest(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	{
		// No Content-Type header is accepted (bodyless requests) when the other
		// confirmations are present.
		delete(bkt.Objects(), path.Join("fake", tsdb.TenantDeletionMarkPath))
		req := httptest.NewRequest(http.MethodPost, "http://cortex/purger/delete_tenant?confirm_tenant=fake", nil)
		req.Header.Set("X-Cortex-Confirm-Delete", "fake")
		req = req.WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
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
