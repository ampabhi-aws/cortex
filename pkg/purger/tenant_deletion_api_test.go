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

func enabledConfig() Config {
	return Config{EnableTenantDeletionAPI: true}
}

func TestDeleteTenant_DisabledByDefault(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, Config{}, log.NewNopLogger())

	ctx := user.InjectOrgID(context.Background(), "fake")
	req := (&http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}).WithContext(ctx)
	resp := httptest.NewRecorder()
	api.DeleteTenant(resp, req)
	require.Equal(t, http.StatusForbidden, resp.Code)
	require.Empty(t, bkt.Objects())
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, enabledConfig(), log.NewNopLogger())

	{
		// No tenant header -> 401
		req := &http.Request{URL: &url.URL{}}
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	}

	{
		// Missing confirmation query param -> 400
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := (&http.Request{URL: &url.URL{}}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	{
		// Mismatched confirmation -> 400
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := (&http.Request{URL: &url.URL{RawQuery: "tenant=other"}}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
		require.Empty(t, bkt.Objects())
	}

	{
		// Correct confirmation -> 200 and mark written
		ctx := user.InjectOrgID(context.Background(), "fake")
		req := (&http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		objs := bkt.Objects()
		require.NotNil(t, objs[path.Join("fake", tsdb.TenantDeletionMarkPath)])
	}
}

func TestCancelDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	api := newTenantDeletionAPI(bkt, nil, enabledConfig(), log.NewNopLogger())

	ctx := user.InjectOrgID(context.Background(), "fake")

	// Nothing to cancel.
	{
		req := (&http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.CancelDeleteTenant(resp, req)
		require.Equal(t, http.StatusNotFound, resp.Code)
	}

	// Write a deletion mark, then cancel it.
	{
		req := (&http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenant(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)])

		req2 := (&http.Request{URL: &url.URL{RawQuery: "tenant=fake"}}).WithContext(ctx)
		resp2 := httptest.NewRecorder()
		api.CancelDeleteTenant(resp2, req2)
		require.Equal(t, http.StatusOK, resp2.Code)
		_, present := bkt.Objects()[path.Join("fake", tsdb.TenantDeletionMarkPath)]
		require.False(t, present, "deletion mark should have been removed")
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

			api := newTenantDeletionAPI(bkt, nil, enabledConfig(), log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}
