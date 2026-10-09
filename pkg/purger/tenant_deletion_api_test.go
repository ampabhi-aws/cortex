package purger

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/alertmanager/alertstore/bucketclient"
	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
	"github.com/cortexproject/cortex/pkg/ruler/rulestore"
	rulebucket "github.com/cortexproject/cortex/pkg/ruler/rulestore/bucketclient"
	"github.com/cortexproject/cortex/pkg/storage/tsdb"
)

func newTestStores(t *testing.T) (rulestore.RuleStore, *bucketclient.BucketAlertStore) {
	t.Helper()
	ruleBkt := objstore.NewInMemBucket()
	alertBkt := objstore.NewInMemBucket()
	ruleStore := rulebucket.NewBucketRuleStore(ruleBkt, nil, log.NewNopLogger())
	alertStore := bucketclient.NewBucketAlertStore(alertBkt, nil, log.NewNopLogger())
	return ruleStore, alertStore
}

func TestDeleteTenant(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	ruleStore, alertStore := newTestStores(t)
	// Seed per-tenant rule group and Alertmanager config/state to prove they are deleted.
	ctx := context.Background()
	require.NoError(t, ruleStore.SetRuleGroup(ctx, "fake", "ns", &rulespb.RuleGroupDesc{Namespace: "ns", Name: "g", User: "fake"}))
	require.NoError(t, alertStore.SetAlertConfig(ctx, alertspb.AlertConfigDesc{User: "fake", RawConfig: "receivers: []\n"}))
	require.NoError(t, alertStore.SetFullState(ctx, "fake", alertspb.FullStateDesc{}))

	api := newTenantDeletionAPI(bkt, ruleStore, alertStore, nil, log.NewNopLogger())

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

		// Rule groups removed.
		groups, err := ruleStore.ListRuleGroupsForUserAndNamespace(ctx, "fake", "")
		require.NoError(t, err)
		require.Empty(t, groups)

		// Alertmanager config and full state removed.
		_, err = alertStore.GetAlertConfig(ctx, "fake")
		require.ErrorIs(t, err, alertspb.ErrNotFound)
		_, err = alertStore.GetFullState(ctx, "fake")
		require.ErrorIs(t, err, alertspb.ErrNotFound)
	}
}

func TestDeleteTenant_FailsClosed_WhenStoresMissing(t *testing.T) {
	bkt := objstore.NewInMemBucket()

	// No ruler store wired in: must 500, not silently succeed.
	api := newTenantDeletionAPI(bkt, nil, nil, nil, log.NewNopLogger())
	ctx := user.InjectOrgID(context.Background(), "fake")
	req := (&http.Request{}).WithContext(ctx)
	resp := httptest.NewRecorder()
	api.DeleteTenant(resp, req)
	require.Equal(t, http.StatusInternalServerError, resp.Code)

	// Ruler wired in but alert store missing: must still 500.
	ruleStore, _ := newTestStores(t)
	api = newTenantDeletionAPI(bkt, ruleStore, nil, nil, log.NewNopLogger())
	resp = httptest.NewRecorder()
	api.DeleteTenant(resp, req)
	require.Equal(t, http.StatusInternalServerError, resp.Code)
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

			api := newTenantDeletionAPI(bkt, nil, nil, nil, log.NewNopLogger())

			res, err := api.isBlocksForUserDeleted(context.Background(), username)
			require.NoError(t, err)
			require.Equal(t, tc.expectedBlocksDeleted, res)
		})
	}
}

func TestDeleteTenantStatus_ReflectsAllStores(t *testing.T) {
	bkt := objstore.NewInMemBucket()
	ruleStore, alertStore := newTestStores(t)

	api := newTenantDeletionAPI(bkt, ruleStore, alertStore, nil, log.NewNopLogger())

	// Seed state so none of the stores are "deleted" yet.
	ctx := user.InjectOrgID(context.Background(), "fake")
	require.NoError(t, ruleStore.SetRuleGroup(ctx, "fake", "ns", &rulespb.RuleGroupDesc{Namespace: "ns", Name: "g", User: "fake"}))
	require.NoError(t, alertStore.SetAlertConfig(ctx, alertspb.AlertConfigDesc{User: "fake", RawConfig: "receivers: []\n"}))

	status := func() DeleteTenantStatusResponse {
		req := (&http.Request{}).WithContext(ctx)
		resp := httptest.NewRecorder()
		api.DeleteTenantStatus(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		var out DeleteTenantStatusResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return out
	}

	got := status()
	require.True(t, got.BlocksDeleted) // no blocks seeded
	require.False(t, got.RuleGroupsDeleted)
	require.False(t, got.AlertmanagerConfigDeleted)
	require.False(t, got.Complete)

	// Delete everything via the API and recheck.
	resp := httptest.NewRecorder()
	api.DeleteTenant(resp, (&http.Request{}).WithContext(ctx))
	require.Equal(t, http.StatusOK, resp.Code)

	got = status()
	require.True(t, got.BlocksDeleted)
	require.True(t, got.RuleGroupsDeleted)
	require.True(t, got.AlertmanagerConfigDeleted)
	require.True(t, got.Complete)

	// With no stores wired in, Complete must be false (fail closed) even though blocks look clean.
	apiNoStores := newTenantDeletionAPI(bkt, nil, nil, nil, log.NewNopLogger())
	req := (&http.Request{}).WithContext(ctx)
	resp = httptest.NewRecorder()
	apiNoStores.DeleteTenantStatus(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var out DeleteTenantStatusResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.True(t, out.BlocksDeleted)
	require.False(t, out.RuleGroupsDeleted)
	require.False(t, out.AlertmanagerConfigDeleted)
	require.False(t, out.Complete)
}
