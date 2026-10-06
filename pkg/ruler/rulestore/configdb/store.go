package configdb

import (
	"context"
	"errors"
	"sync"

	"github.com/cortexproject/cortex/pkg/configs/client"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
)

const (
	Name = "configdb"
)

// ConfigRuleStore is a concrete implementation of RuleStore that sources rules
// from the config service.
//
// The mutable cache (ruleGroupList and the since cursor) is guarded by mtx
// because ListAllRuleGroups is reached from many goroutines in parallel: the
// unauthenticated /ruler/rule_groups endpoint fans out via
// concurrency.ForEachUser with fetchRulesConcurrency=16, and the ruler sync
// loop fans out with loadRulesConcurrency=10 on the same instance. Without
// the mutex, concurrent writes to the Go map are detected by the runtime and
// abort the process with an unrecoverable fatal error.
type ConfigRuleStore struct {
	configClient client.Client

	mtx           sync.Mutex
	since         userconfig.ID
	ruleGroupList map[string]rulespb.RuleGroupList
}

func (c *ConfigRuleStore) SupportsModifications() bool {
	return false
}

// NewConfigRuleStore constructs a ConfigRuleStore
func NewConfigRuleStore(c client.Client) *ConfigRuleStore {
	return &ConfigRuleStore{
		configClient:  c,
		since:         0,
		ruleGroupList: make(map[string]rulespb.RuleGroupList),
	}
}

func (c *ConfigRuleStore) ListAllUsers(ctx context.Context) ([]string, error) {
	m, err := c.ListAllRuleGroups(ctx)

	// TODO: this should be optimized, if possible.
	result := make([]string, 0, len(m))
	for u := range m {
		result = append(result, u)
	}

	return result, err
}

// ListAllRuleGroups implements RuleStore
func (c *ConfigRuleStore) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
	// Snapshot `since` under the lock so we don't observe a torn read.
	c.mtx.Lock()
	since := c.since
	c.mtx.Unlock()

	configs, err := c.configClient.GetRules(ctx, since)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	for user, cfg := range configs {
		userRules := rulespb.RuleGroupList{}
		if cfg.IsDeleted() {
			delete(c.ruleGroupList, user)
			continue
		}
		rMap, err := cfg.Config.ParseFormatted()
		if err != nil {
			return nil, err
		}
		for file, rgs := range rMap {
			for _, rg := range rgs.Groups {
				userRules = append(userRules, rulespb.ToProto(user, file, rg))
			}
		}
		c.ruleGroupList[user] = userRules
	}

	if id := getLatestConfigID(configs, c.since); id > c.since {
		c.since = id
	}

	// Return a copy so callers can never observe or mutate the live cache,
	// which would race with subsequent reloads or corrupt the cached slices
	// via in-place slice operations (append, re-slicing).
	out := make(map[string]rulespb.RuleGroupList, len(c.ruleGroupList))
	for k, v := range c.ruleGroupList {
		cp := make(rulespb.RuleGroupList, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out, nil
}

// getLatestConfigID gets the latest configs ID.
// max [latest, max (map getID cfgs)]
func getLatestConfigID(cfgs map[string]userconfig.VersionedRulesConfig, latest userconfig.ID) userconfig.ID {
	ret := latest
	for _, config := range cfgs {
		if config.ID > ret {
			ret = config.ID
		}
	}
	return ret
}

func (c *ConfigRuleStore) ListRuleGroupsForUserAndNamespace(ctx context.Context, userID string, namespace string) (rulespb.RuleGroupList, error) {
	r, err := c.ListAllRuleGroups(ctx)
	if err != nil {
		return nil, err
	}

	list := r[userID]
	if namespace == "" {
		return list, nil
	}

	// Build a fresh filtered slice. The previous in-place filter
	// (`list = append(list[:ix], list[ix+1:]...)`) mutated the cached
	// backing array returned by ListAllRuleGroups, corrupting rule-group
	// lists for subsequent callers.
	filtered := make(rulespb.RuleGroupList, 0, len(list))
	for _, rg := range list {
		if rg.GetNamespace() == namespace {
			filtered = append(filtered, rg)
		}
	}
	return filtered, nil
}

func (c *ConfigRuleStore) LoadRuleGroups(ctx context.Context, groupsToLoad map[string]rulespb.RuleGroupList) error {
	// Since ConfigRuleStore already Loads the rules in the List methods, there is nothing left to do here.
	return nil
}

// GetRuleGroup is not implemented
func (c *ConfigRuleStore) GetRuleGroup(ctx context.Context, userID, namespace, group string) (*rulespb.RuleGroupDesc, error) {
	return nil, errors.New("not implemented by the config service rule store")
}

// SetRuleGroup is not implemented
func (c *ConfigRuleStore) SetRuleGroup(ctx context.Context, userID, namespace string, group *rulespb.RuleGroupDesc) error {
	return errors.New("not implemented by the config service rule store")
}

// DeleteRuleGroup is not implemented
func (c *ConfigRuleStore) DeleteRuleGroup(ctx context.Context, userID, namespace string, group string) error {
	return errors.New("not implemented by the config service rule store")
}

// DeleteNamespace is not implemented
func (c *ConfigRuleStore) DeleteNamespace(ctx context.Context, userID, namespace string) error {
	return errors.New("not implemented by the config service rule store")
}
