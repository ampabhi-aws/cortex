package configdb

import (
	"context"
	fmt "fmt"
	"testing"
	time "time"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/util/concurrency"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/configs/client"
)

var zeroTime time.Time

type MockClient struct {
	cfgs map[string]userconfig.VersionedRulesConfig
	err  error
}

func (c *MockClient) GetRules(ctx context.Context, since userconfig.ID) (map[string]userconfig.VersionedRulesConfig, error) {
	return c.cfgs, c.err
}

func (c *MockClient) GetAlerts(ctx context.Context, since userconfig.ID) (*client.ConfigsResponse, error) {
	return nil, nil
}

func Test_ConfigRuleStoreError(t *testing.T) {
	mock := &MockClient{
		cfgs: nil,
		err:  fmt.Errorf("Error"),
	}

	store := NewConfigRuleStore(mock)
	_, err := store.ListAllRuleGroups(context.Background())

	assert.Equal(t, mock.err, err, "Unexpected error returned")
}

func Test_ConfigRuleStoreReturn(t *testing.T) {
	id := userconfig.ID(10)
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        id,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)
	rules, _ := store.ListAllRuleGroups(context.Background())

	assert.Equal(t, 1, len(rules["user"]))
	assert.Equal(t, id, store.since)
}

func Test_ConfigRuleStoreDelete(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        1,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)
	_, _ = store.ListAllRuleGroups(context.Background())

	mock.cfgs["user"] = userconfig.VersionedRulesConfig{
		ID:        1,
		Config:    userconfig.RulesConfig{},
		DeletedAt: time.Unix(0, 1),
	}

	rules, _ := store.ListAllRuleGroups(context.Background())

	assert.Equal(t, 0, len(rules["user"]))
}

func Test_ConfigRuleStoreAppend(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        1,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)
	_, _ = store.ListAllRuleGroups(context.Background())

	delete(mock.cfgs, "user")
	mock.cfgs["user2"] = userconfig.VersionedRulesConfig{
		ID:        1,
		Config:    fakeRuleConfig(),
		DeletedAt: zeroTime,
	}

	rules, _ := store.ListAllRuleGroups(context.Background())

	assert.Equal(t, 2, len(rules))
}

func Test_ConfigRuleStoreSinceSet(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        1,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
			"user1": {
				ID:        10,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
			"user2": {
				ID:        100,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)
	_, _ = store.ListAllRuleGroups(context.Background())
	assert.Equal(t, userconfig.ID(100), store.since)

	delete(mock.cfgs, "user")
	delete(mock.cfgs, "user1")
	mock.cfgs["user2"] = userconfig.VersionedRulesConfig{
		ID:        50,
		Config:    fakeRuleConfig(),
		DeletedAt: zeroTime,
	}

	_, _ = store.ListAllRuleGroups(context.Background())
	assert.Equal(t, userconfig.ID(100), store.since)

	mock.cfgs["user2"] = userconfig.VersionedRulesConfig{
		ID:        101,
		Config:    fakeRuleConfig(),
		DeletedAt: zeroTime,
	}

	_, _ = store.ListAllRuleGroups(context.Background())
	assert.Equal(t, userconfig.ID(101), store.since)
}

func fakeRuleConfig() userconfig.RulesConfig {
	return userconfig.RulesConfig{
		FormatVersion: userconfig.RuleFormatV2,
		Files: map[string]string{
			"test": `
# Config no. 1.
groups:
- name: example
  rules:
  - alert: ScrapeFailed
    expr: 'up != 1'
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Scrape of {{$labels.job}} (pod: {{$labels.instance}}) failed."
      description: "Prometheus cannot reach the /metrics page on the {{$labels.instance}} pod."
      impact: "We have no monitoring data for {{$labels.job}} - {{$labels.instance}}. At worst, it's completely down. At best, we cannot reliably respond to operational issues."
      dashboardURL: "$${base_url}/admin/prometheus/targets"
`,
		},
	}
}

// Test_ConfigRuleStoreListNamespaceDoesNotMutateCache ensures that filtering
// by namespace never mutates the cached backing slice. Previously the filter
// used an in-place `append(list[:ix], list[ix+1:]...)` which corrupted the
// cached rule-group list for subsequent callers.
func Test_ConfigRuleStoreListNamespaceDoesNotMutateCache(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        1,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
	}

	store := NewConfigRuleStore(mock)

	before, err := store.ListAllRuleGroups(context.Background())
	require.NoError(t, err)
	originalLen := len(before["user"])
	require.Equal(t, 1, originalLen)
	originalNamespace := before["user"][0].GetNamespace()

	// Filter for a namespace that cannot match, which previously spliced the
	// cached slice down to zero length.
	filtered, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "does-not-exist")
	require.NoError(t, err)
	require.Equal(t, 0, len(filtered))

	after, err := store.ListAllRuleGroups(context.Background())
	require.NoError(t, err)
	require.Equal(t, originalLen, len(after["user"]), "filter must not mutate the cached rule-group list")
	require.Equal(t, originalNamespace, after["user"][0].GetNamespace())
}

// Test_ConfigRuleStoreConcurrentListAllRuleGroups is the regression test for
// the concurrent-map-writes vulnerability. It drives the store through
// concurrency.ForEachUser with multiple tenants (mirroring the production
// unauthenticated /ruler/rule_groups endpoint, which fans out with
// fetchRulesConcurrency=16). Run with `go test -race` to catch regressions.
func Test_ConfigRuleStoreConcurrentListAllRuleGroups(t *testing.T) {
	cfgs := map[string]userconfig.VersionedRulesConfig{}
	users := []string{"t1", "t2", "t3", "t4"}
	for i, u := range users {
		cfgs[u] = userconfig.VersionedRulesConfig{
			ID:        userconfig.ID(i + 1),
			Config:    fakeRuleConfig(),
			DeletedAt: zeroTime,
		}
	}
	mock := &MockClient{cfgs: cfgs}
	store := NewConfigRuleStore(mock)

	err := concurrency.ForEachUser(context.Background(), users, 16, func(ctx context.Context, userID string) error {
		_, err := store.ListRuleGroupsForUserAndNamespace(ctx, userID, "")
		return err
	})
	require.NoError(t, err)
}
