package configdb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/configs/client"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/util/concurrency"
)

type mockConfigClient struct {
	configs *client.ConfigsResponse
}

func (m *mockConfigClient) GetRules(ctx context.Context, since userconfig.ID) (map[string]userconfig.VersionedRulesConfig, error) {
	return nil, nil
}

func (m *mockConfigClient) GetAlerts(ctx context.Context, since userconfig.ID) (*client.ConfigsResponse, error) {
	return m.configs, nil
}

func buildConfigsResponse(users []string) *client.ConfigsResponse {
	views := map[string]userconfig.View{}
	for i, u := range users {
		views[u] = userconfig.View{
			ID: userconfig.ID(i + 1),
			Config: userconfig.Config{
				AlertmanagerConfig: "route:\n  receiver: w\nreceivers:\n  - name: w\n",
			},
			DeletedAt: time.Time{},
		}
	}
	return &client.ConfigsResponse{Configs: views}
}

// Test_ConcurrentGetAlertConfig is the regression test for the
// concurrent-map-writes vulnerability on the alertmanager configdb store. It
// drives the store through concurrency.ForEachUser with multiple tenants,
// mirroring the production unauthenticated multitenant_alertmanager configs
// endpoint which fans out with fetchConcurrency=16. Run with go test -race
// to catch regressions on the alertConfigs map and since cursor.
func Test_ConcurrentGetAlertConfig(t *testing.T) {
	users := []string{"t1", "t2", "t3", "t4"}
	mock := &mockConfigClient{configs: buildConfigsResponse(users)}
	store := NewStore(mock)

	err := concurrency.ForEachUser(context.Background(), users, 16, func(ctx context.Context, userID string) error {
		_, err := store.GetAlertConfig(ctx, userID)
		return err
	})
	require.NoError(t, err)
}

// Test_GetAlertConfigsReturnsCopy ensures callers cannot mutate the live cache.
func Test_GetAlertConfigsReturnsCopy(t *testing.T) {
	users := []string{"t1", "t2"}
	mock := &mockConfigClient{configs: buildConfigsResponse(users)}
	store := NewStore(mock)

	cfgs, err := store.GetAlertConfigs(context.Background(), users)
	require.NoError(t, err)
	require.Len(t, cfgs, 2)

	// Mutate the returned map; this must not affect subsequent reads.
	delete(cfgs, "t1")

	cfgs2, err := store.GetAlertConfigs(context.Background(), users)
	require.NoError(t, err)
	require.Len(t, cfgs2, 2, "returned map must be a copy")
}
