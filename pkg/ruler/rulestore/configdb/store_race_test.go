package configdb

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// TestConcurrentListRaces exercises ConfigRuleStore from many goroutines to
// make sure concurrent access does not race or crash with "concurrent map
// writes". Run with `go test -race`.
func TestConcurrentListRaces(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        userconfig.ID(10),
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
			"user2": {
				ID:        userconfig.ID(11),
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)

	const goroutines = 16
	const iterations = 500

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user1", "")
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				_, err = store.ListAllRuleGroups(context.Background())
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestListRuleGroupsForUserAndNamespaceDoesNotCorruptCache verifies the
// namespace filter does not mutate the cached rule-group list in place.
func TestListRuleGroupsForUserAndNamespaceDoesNotCorruptCache(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        userconfig.ID(10),
				Config:    fakeMultiNamespaceRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)

	// Prime the cache.
	all, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	totalBefore := len(all["user1"])
	assert.Greater(t, totalBefore, 1, "expected multiple cached rule groups for user1")

	// Repeatedly filter by one namespace. Pre-fix, this would corrupt the
	// cached backing array by shifting elements in place.
	for i := 0; i < 10; i++ {
		_, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "user1", "ns-a")
		assert.NoError(t, err)
	}

	// The cache must still contain the full set.
	store.mtx.Lock()
	cached := store.ruleGroupList["user1"]
	store.mtx.Unlock()
	assert.Equal(t, totalBefore, len(cached), "cache length must not shrink after namespace-filtered reads")

	seen := map[string]int{}
	for _, g := range cached {
		seen[g.GetNamespace()]++
	}
	// There must be at least two distinct namespaces still cached.
	assert.GreaterOrEqual(t, len(seen), 2, "namespace diversity must be preserved")
}

// TestListAllRuleGroupsReturnsCopy ensures callers cannot mutate the cache
// via the returned map.
func TestListAllRuleGroupsReturnsCopy(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        userconfig.ID(10),
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
			"user2": {
				ID:        userconfig.ID(11),
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
		err: nil,
	}

	store := NewConfigRuleStore(mock)
	first, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Len(t, first, 2)

	// Mutating the returned map must not affect the cache.
	delete(first, "user1")

	store.mtx.Lock()
	cachedLen := len(store.ruleGroupList)
	store.mtx.Unlock()
	assert.Equal(t, 2, cachedLen, "mutating returned map must not change cached state")

	// A subsequent call must still see both users.
	second, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Len(t, second, 2)
}

func fakeMultiNamespaceRuleConfig() userconfig.RulesConfig {
	return userconfig.RulesConfig{
		FormatVersion: userconfig.RuleFormatV2,
		Files: map[string]string{
			"ns-a": "groups:\n- name: group-a1\n  rules:\n  - alert: A1\n    expr: vector(1)\n- name: group-a2\n  rules:\n  - alert: A2\n    expr: vector(1)\n",
			"ns-b": "groups:\n- name: group-b1\n  rules:\n  - alert: B1\n    expr: vector(1)\n",
		},
	}
}
