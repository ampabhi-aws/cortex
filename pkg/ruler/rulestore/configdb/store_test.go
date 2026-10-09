package configdb

import (
	"context"
	fmt "fmt"
	"testing"
	time "time"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"

	"github.com/stretchr/testify/assert"

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

// fakeMultiNamespaceRuleConfig returns a rules config with three namespaces
// (ns1, ns2, ns3), each containing a single group. This is used to exercise
// filtering behaviour of ListRuleGroupsForUserAndNamespace against the cache.
func fakeMultiNamespaceRuleConfig() userconfig.RulesConfig {
	ruleFile := func(groupName string) string {
		return fmt.Sprintf(`
groups:
- name: %s
  rules:
  - alert: ScrapeFailed
    expr: 'up != 1'
    for: 10m
    labels:
      severity: warning
`, groupName)
	}
	return userconfig.RulesConfig{
		FormatVersion: userconfig.RuleFormatV2,
		Files: map[string]string{
			"ns1": ruleFile("g1"),
			"ns2": ruleFile("g2"),
			"ns3": ruleFile("g3"),
		},
	}
}

// Test_ConfigRuleStoreListForUserAndNamespace_DoesNotCorruptCache is a
// regression test for the bug where ListRuleGroupsForUserAndNamespace
// filtered the cached slice in place with append(list[:ix], list[ix+1:]...),
// permanently corrupting the cache for the tenant and silently dropping
// unrelated rule groups on subsequent reads. After filtering by one
// namespace, a subsequent unfiltered call must still return all original
// rule groups.
func Test_ConfigRuleStoreListForUserAndNamespace_DoesNotCorruptCache(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user": {
				ID:        1,
				Config:    fakeMultiNamespaceRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)

	// Prime the cache.
	all, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(all), "expected 3 rule groups for user prior to filtered call")

	// Filter by ns3 — this used to corrupt the cached slice in place.
	ns3, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "ns3")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ns3), "expected exactly one rule group in ns3")
	assert.Equal(t, "ns3", ns3[0].GetNamespace())

	// Simulate the ruler sync-loop advancing c.since so unchanged users are
	// not re-populated on the next call. The scanner's claim is that even
	// then the cache must still contain all three namespaces.
	mock.cfgs = map[string]userconfig.VersionedRulesConfig{}

	// A subsequent unfiltered call must still return all three groups.
	again, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(again), "cache corruption: unfiltered call should still return all 3 rule groups")

	seen := map[string]int{}
	for _, g := range again {
		seen[g.GetNamespace()]++
	}
	assert.Equal(t, 1, seen["ns1"], "ns1 must still be present in the cache")
	assert.Equal(t, 1, seen["ns2"], "ns2 must still be present in the cache")
	assert.Equal(t, 1, seen["ns3"], "ns3 must still be present in the cache")

	// The returned slice must also be independent of the cache: mutating it
	// must not affect subsequent reads.
	if len(again) > 0 {
		again[0] = nil
	}
	final, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(final))
	for _, g := range final {
		assert.NotNil(t, g, "cache entry must not be nil after caller mutates returned slice")
	}
}
