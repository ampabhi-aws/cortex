package configdb

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// fetchRulesConcurrency mirrors the fan-out used by Ruler.ListAllRules
// (pkg/ruler/ruler.go). Keep this in sync when the ruler changes its value.
const fetchRulesConcurrency = 16

// TestConfigRuleStoreRace exercises ConfigRuleStore from fetchRulesConcurrency
// goroutines, mirroring the handler fan-out driven by GET /ruler/rule_groups.
// It must pass under "go test -race".
func TestConfigRuleStoreRace(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        1,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
			"user2": {
				ID:        2,
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)

	const iters = 200
	var wg sync.WaitGroup
	wg.Add(fetchRulesConcurrency)
	for i := 0; i < fetchRulesConcurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if _, err := store.ListAllRuleGroups(context.Background()); err != nil {
					t.Errorf("ListAllRuleGroups: %v", err)
					return
				}
				if _, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user1", ""); err != nil {
					t.Errorf("ListRuleGroupsForUserAndNamespace: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestConfigRuleStoreListRuleGroupsForUserAndNamespaceDoesNotCorruptCache asserts
// that namespace-filtering does not mutate the cached rule-group list in place.
func TestConfigRuleStoreListRuleGroupsForUserAndNamespaceDoesNotCorruptCache(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        1,
				Config:    fakeMultiNamespaceRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)

	before, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 3, len(before["user1"]))

	mock.cfgs = map[string]userconfig.VersionedRulesConfig{}

	filtered, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user1", "ns2")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(filtered))
	assert.Equal(t, "ns2", filtered[0].GetNamespace())

	after, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 3, len(after["user1"]))

	seen := map[string]int{}
	for _, g := range after["user1"] {
		seen[g.GetNamespace()]++
	}
	assert.Equal(t, 1, seen["ns1"], "ns1 should appear exactly once")
	assert.Equal(t, 1, seen["ns2"], "ns2 should appear exactly once")
	assert.Equal(t, 1, seen["ns3"], "ns3 should appear exactly once")
}

// TestConfigRuleStoreListAllRuleGroupsReturnsCopy ensures callers cannot mutate the
// internal cache by writing to the returned map.
func TestConfigRuleStoreListAllRuleGroupsReturnsCopy(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {ID: 1, Config: fakeRuleConfig(), DeletedAt: zeroTime},
			"user2": {ID: 2, Config: fakeRuleConfig(), DeletedAt: zeroTime},
		},
	}

	store := NewConfigRuleStore(mock)

	first, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(first))

	delete(first, "user1")

	mock.cfgs = map[string]userconfig.VersionedRulesConfig{}

	second, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(second), "mutating the returned map must not affect the cache")
}

func fakeMultiNamespaceRuleConfig() userconfig.RulesConfig {
	return userconfig.RulesConfig{
		FormatVersion: userconfig.RuleFormatV2,
		Files: map[string]string{
			"ns1": "groups:\n- name: g1\n  rules:\n  - alert: A1\n    expr: 'up != 1'\n",
			"ns2": "groups:\n- name: g2\n  rules:\n  - alert: A2\n    expr: 'up != 1'\n",
			"ns3": "groups:\n- name: g3\n  rules:\n  - alert: A3\n    expr: 'up != 1'\n",
		},
	}
}
