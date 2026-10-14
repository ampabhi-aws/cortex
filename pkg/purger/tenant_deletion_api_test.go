package purger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	api := newTenantDeletionAPI(bkt, nil, true, log.NewNopLogger())

	// Missing X-Scope-OrgID -> 401.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{URL: &url.URL{}})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Missing confirmation parameter -> 400 and no deletion mark written.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{URL: &url.URL{}}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Confirmation parameter present but does not match context tenant -> 400.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{URL: &url.URL{RawQuery: "tenant=other"}}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Matching confirmation parameter -> 200, mark written.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}
}

func TestDeleteTenantAuthDisabledRefused(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, false, log.NewNopLogger())

	ctx := context.Background()
	ctx = user.InjectOrgID(ctx, "fake")

	req := &http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}
	resp := httptest.NewRecorder()
	api.DeleteTenant(resp, req.WithContext(ctx))

	require.Equal(t, http.StatusForbidden, resp.Code)
	require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
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

			api := newTenantDeletionAPI(bkt, nil, true, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
