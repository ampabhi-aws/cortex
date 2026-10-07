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
	api := newTenantDeletionAPI(bkt, nil, log.NewNopLogger())

	{
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, &http.Request{})
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	{
		// Unknown tenant (no data in the bucket) must be rejected so that this
		// endpoint cannot be used to mint arbitrary new top-level prefixes.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusNotFound, resp.Code)
		require.Nil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}

	{
		// Invalid tenant ID (unsupported character) must be rejected.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "bad tenant")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Tenant ID longer than 150 chars must be rejected.
		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, strings.Repeat("a", 151))

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusBadRequest, resp.Code)
	}

	{
		// Known tenant (with existing data) is accepted and a deletion mark is written.
		require.NoError(t, bkt.Upload(context.Background(), path.Join("fake", "01EQK4QKFHVSZYVJ908Y7HH9E0", "meta.json"), bytes.NewReader([]byte("data"))))

		ctx := context.Background()
		ctx = user.InjectOrgID(ctx, "fake")

		req := &http.Request{}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req.WithContext(ctx))

		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
		firstMark := objs[path.Join("fake", tsdb.TenantDeletionMarkPath)]

		// A repeated POST for the same tenant must be a no-op (idempotent) so
		// that finished_time cannot be reset to keep the prefix alive forever.
		resp2 := httptest.NewRecorder()
		api.DeleteTenant(resp2, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, resp2.Code)
		require.Equal(t, firstMark, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])
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
