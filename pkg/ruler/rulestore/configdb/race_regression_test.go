package configdb

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// Test_ConcurrentListIsRaceFree exercises the store from many goroutines concurrently to
// catch regressions of the missing-synchronisation bug (concurrent map writes to
// ruleGroupList and unsynchronised writes to since). Run with -race to make this test
// most meaningful; without the race detector it still asserts the Go runtime does not
// abort with "fatal error: concurrent map writes".
func Test_ConcurrentListIsRaceFree(t *testing.T) {
	cfgs := map[string]userconfig.VersionedRulesConfig{}
	for _, u := range []string{"user1", "user2", "user3", "user4"} {
		cfgs[u] = userconfig.VersionedRulesConfig{
			ID:        userconfig.ID(1),
			Config:    fakeRuleConfig(),
			DeletedAt: zeroTime,
		}
	}
	store := NewConfigRuleStore(&MockClient{cfgs: cfgs})

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			if i%2 == 0 {
				_, err := store.ListAllRuleGroups(ctx)
				assert.NoError(t, err)
			} else {
				_, err := store.ListRuleGroupsForUserAndNamespace(ctx, "user1", "")
				assert.NoError(t, err)
			}
			_, err := store.ListRuleGroupsForUserAndNamespace(ctx, "user1", "does-not-match")
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
}

// Test_NamespaceFilterDoesNotCorruptCache verifies that filtering by a non-matching
// namespace does not corrupt the cached rule-group slice. Prior to the fix the in-place
// append rewrote the backing array of the cached slice, leaving duplicated/dropped
// entries that persisted because GetRules is incremental.
func Test_NamespaceFilterDoesNotCorruptCache(t *testing.T) {
	mock := &MockClient{
		cfgs: map[string]userconfig.VersionedRulesConfig{
			"user1": {
				ID:        userconfig.ID(1),
				Config:    fakeRuleConfig(),
				DeletedAt: zeroTime,
			},
		},
	}
	store := NewConfigRuleStore(mock)

	ctx := context.Background()
	before, err := store.ListAllRuleGroups(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, before["user1"])

	type key struct{ ns, name string }
	toKeys := func(user string) []key {
		store.mtx.Lock()
		defer store.mtx.Unlock()
		out := make([]key, 0, len(store.ruleGroupList[user]))
		for _, g := range store.ruleGroupList[user] {
			out = append(out, key{ns: g.GetNamespace(), name: g.GetName()})
		}
		return out
	}
	cachedBefore := toKeys("user1")

	filtered, err := store.ListRuleGroupsForUserAndNamespace(ctx, "user1", "namespace-that-does-not-exist")
	require.NoError(t, err)
	assert.Len(t, filtered, 0)

	cachedAfter := toKeys("user1")
	assert.Equal(t, cachedBefore, cachedAfter, "namespace filtering must not mutate the cached slice")
}
