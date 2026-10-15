package ruler

import (
	"context"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/notifier"
	promRules "github.com/prometheus/prometheus/rules"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	"gopkg.in/yaml.v3"

	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
	"github.com/cortexproject/cortex/pkg/util/test"
)

func TestSyncRuleGroups(t *testing.T) {
	dir := t.TempDir()

	m, err := NewDefaultMultiTenantManager(Config{RulePath: dir}, factory, nil, log.NewNopLogger())
	require.NoError(t, err)

	const user = "testUser"

	userRules := map[string]rulespb.RuleGroupList{
		user: {
			&rulespb.RuleGroupDesc{
				Name:      "group1",
				Namespace: "ns",
				Interval:  1 * time.Minute,
				User:      user,
			},
		},
	}
	m.SyncRuleGroups(context.Background(), userRules)

	mgr := getManager(m, user)
	require.NotNil(t, mgr)

	test.Poll(t, 1*time.Second, true, func() interface{} {
		return mgr.(*mockRulesManager).running.Load()
	})

	// Verify that user rule groups are now cached locally and notifiers are created.
	{
		users, err := m.mapper.users()
		_, ok := m.notifiers[user]
		require.NoError(t, err)
		require.Equal(t, []string{user}, users)
		require.True(t, ok)
	}

	// Passing empty map / nil stops all managers.
	m.SyncRuleGroups(context.Background(), nil)
	require.Nil(t, getManager(m, user))

	// Make sure old manager was stopped.
	test.Poll(t, 1*time.Second, false, func() interface{} {
		return mgr.(*mockRulesManager).running.Load()
	})

	// Verify that local rule groups were removed.
	{
		users, err := m.mapper.users()
		_, ok := m.notifiers[user]
		require.NoError(t, err)
		require.Equal(t, []string(nil), users)
		require.False(t, ok)
	}

	// Resync same rules as before. Previously this didn't restart the manager.
	m.SyncRuleGroups(context.Background(), userRules)

	newMgr := getManager(m, user)
	require.NotNil(t, newMgr)
	require.True(t, mgr != newMgr)

	test.Poll(t, 1*time.Second, true, func() interface{} {
		return newMgr.(*mockRulesManager).running.Load()
	})

	// Verify that user rule groups are cached locally again.
	{
		users, err := m.mapper.users()
		require.NoError(t, err)
		require.Equal(t, []string{user}, users)
	}

	m.Stop()

	test.Poll(t, 1*time.Second, false, func() interface{} {
		return newMgr.(*mockRulesManager).running.Load()
	})
}

func getManager(m *DefaultMultiTenantManager, user string) RulesManager {
	m.userManagerMtx.Lock()
	defer m.userManagerMtx.Unlock()

	return m.userManagers[user]
}

func factory(_ context.Context, _ string, _ *notifier.Manager, _ log.Logger, _ prometheus.Registerer) RulesManager {
	return &mockRulesManager{done: make(chan struct{})}
}

type mockRulesManager struct {
	running atomic.Bool
	done    chan struct{}
}

func (m *mockRulesManager) Run() {
	m.running.Store(true)
	<-m.done
}

func (m *mockRulesManager) Stop() {
	m.running.Store(false)
	close(m.done)
}

func (m *mockRulesManager) Update(_ time.Duration, _ []string, _ labels.Labels, _ string, _ promRules.RuleGroupPostProcessFunc) error {
	return nil
}

func (m *mockRulesManager) RuleGroups() []*promRules.Group {
	return nil
}

func TestValidateRuleGroupMinInterval(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{RulePath: dir, MinRuleEvaluationInterval: 10 * time.Second}
	m, err := NewDefaultMultiTenantManager(cfg, factory, nil, log.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(m.Stop)

	record := yaml.Node{}
	record.SetString("up_rule")
	expr := yaml.Node{}
	expr.SetString("up")
	validRules := []rulefmt.RuleNode{{Record: record, Expr: expr}}

	// A group below the configured minimum must be rejected.
	errs := m.ValidateRuleGroup(rulefmt.RuleGroup{
		Name:     "spin",
		Interval: model.Duration(time.Millisecond),
		Rules:    validRules,
	})
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "below the minimum allowed evaluation interval")

	// A group at or above the minimum is accepted.
	errs = m.ValidateRuleGroup(rulefmt.RuleGroup{
		Name:     "ok",
		Interval: model.Duration(30 * time.Second),
		Rules:    validRules,
	})
	require.Empty(t, errs)

	// A zero/unset interval is accepted because the ruler falls back to the
	// configured default.
	errs = m.ValidateRuleGroup(rulefmt.RuleGroup{
		Name:  "default",
		Rules: validRules,
	})
	require.Empty(t, errs)

	// When the minimum is unset, any positive interval is permitted (preserves
	// pre-fix behaviour for operators that have not opted in).
	m2, err := NewDefaultMultiTenantManager(Config{RulePath: t.TempDir()}, factory, nil, log.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(m2.Stop)
	errs = m2.ValidateRuleGroup(rulefmt.RuleGroup{
		Name:     "spin",
		Interval: model.Duration(time.Millisecond),
		Rules:    validRules,
	})
	require.Empty(t, errs)
}

func TestSyncRulesClampsIntervalBelowMinimum(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{RulePath: dir, MinRuleEvaluationInterval: 10 * time.Second}
	m, err := NewDefaultMultiTenantManager(cfg, factory, nil, log.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(m.Stop)

	groups := rulespb.RuleGroupList{
		&rulespb.RuleGroupDesc{
			Name:      "spin",
			Namespace: "ns",
			Interval:  time.Millisecond,
			User:      "attacker",
		},
		&rulespb.RuleGroupDesc{
			Name:      "ok",
			Namespace: "ns",
			Interval:  30 * time.Second,
			User:      "attacker",
		},
	}
	m.SyncRuleGroups(context.Background(), map[string]rulespb.RuleGroupList{"attacker": groups})

	require.Equal(t, 10*time.Second, groups[0].Interval, "sub-minimum interval must be clamped")
	require.Equal(t, 30*time.Second, groups[1].Interval, "intervals at or above the minimum are preserved")
}
