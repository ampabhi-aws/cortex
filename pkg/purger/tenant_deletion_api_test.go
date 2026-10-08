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

	// Missing X-Scope-OrgID -> 401.
	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	// Tenant ID with unsupported characters -> 400 (regardless of resolver).
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "has space")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	// Tenant with no data in the bucket -> 404, and no marker is written.
	{
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusNotFound, resp.Code)
		objs := bkt.Objects()
		require.Nil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	// Tenant with data in the bucket -> 200 and marker is written.
	{
		require.NoError(t, bkt.Upload(context.Background(), path.Join("real", "01EQK4QKFHVSZYVJ908Y7HH9E0", "meta.json"), bytes.NewReader([]byte("data"))))

		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "real")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("real", tsdb.TenantDeletionMarkPath)])
	}

	// Repeated calls for a tenant that already has a marker are idempotent
	// and do not re-upload the marker.
	{
		markerKey := path.Join("real", tsdb.TenantDeletionMarkPath)
		before := bkt.Objects()[markerKey]
		require.NotNil(t, before)

		// Mutate the marker to detect a re-upload.
		require.NoError(t, bkt.Upload(context.Background(), markerKey, bytes.NewReader([]byte("sentinel"))))

		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "real")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, []byte("sentinel"), bkt.Objects()[markerKey], "marker must not be re-uploaded")
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
