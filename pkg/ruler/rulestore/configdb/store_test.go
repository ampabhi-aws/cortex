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

// Test_ConfigRuleStoreConcurrent exercises ListAllRuleGroups and
// ListRuleGroupsForUserAndNamespace from many goroutines, mirroring the
// 16-way fetchRulesConcurrency and 10-way loadRulesConcurrency fan-outs in
// pkg/ruler/ruler.go. It is intended to be run with -race: on an
// unsynchronised implementation the Go runtime raises
// "fatal error: concurrent map writes" or the race detector flags
// concurrent map access. It also verifies that namespace filtering never
// mutates the cache (regression test for the in-place filter at the old
// store.go:104).
func Test_ConfigRuleStoreConcurrent(t *testing.T) {
	cfgs := map[string]userconfig.VersionedRulesConfig{}
	for i := 0; i < 8; i++ {
		cfgs[fmt.Sprintf("user-%d", i)] = userconfig.VersionedRulesConfig{
			ID:        userconfig.ID(i + 1),
			Config:    fakeRuleConfig(),
			DeletedAt: zeroTime,
		}
	}
	mock := &MockClient{cfgs: cfgs}
	store := NewConfigRuleStore(mock)

	// Prime the cache so the "concurrent reads" phase has something to see.
	_, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)

	const (
		fetchGoroutines = 16 // matches ruler.fetchRulesConcurrency
		loadGoroutines  = 10 // matches ruler.loadRulesConcurrency
		iterations      = 50
	)

	done := make(chan struct{})
	for i := 0; i < fetchGoroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				_, err := store.ListAllRuleGroups(context.Background())
				assert.NoError(t, err)
			}
		}()
	}
	for i := 0; i < loadGoroutines; i++ {
		userID := fmt.Sprintf("user-%d", i%8)
		go func(uid string) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				_, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), uid, "")
				assert.NoError(t, err)
				// Namespace filter path — on the unfixed implementation
				// this mutates the shared cached slice in place.
				_, err = store.ListRuleGroupsForUserAndNamespace(context.Background(), uid, "does-not-exist")
				assert.NoError(t, err)
			}
		}(userID)
	}
	for i := 0; i < fetchGoroutines+loadGoroutines; i++ {
		<-done
	}

	// After the hammering, every tenant must still have exactly one rule
	// group (fakeRuleConfig produces a single group). Any value other
	// than 1 means the namespace filter mutated the cache.
	all, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	for user, list := range all {
		assert.Equalf(t, 1, len(list), "cache corrupted for %s: got %d groups", user, len(list))
	}
}

// Test_ConfigRuleStoreReturnsCopy asserts that callers can mutate the map
// and slices returned by ListAllRuleGroups without corrupting the cache.
func Test_ConfigRuleStoreReturnsCopy(t *testing.T) {
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

	first, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(first["user"]))

	// Mutate the returned map and slice.
	delete(first, "user")
	for k := range first {
		first[k] = nil
	}

	// The cache must be unaffected.
	second, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(second["user"]))

	// Namespace filter must not corrupt the cache either.
	_, err = store.ListRuleGroupsForUserAndNamespace(context.Background(), "user", "does-not-exist")
	assert.NoError(t, err)

	third, err := store.ListAllRuleGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(third["user"]))
}
