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

// ConfigRuleStore is a concrete implementation of RuleStore that sources rules from the config service.
//
// The same instance is shared between the ruler's periodic sync goroutine and every HTTP
// handler, so all access to the cache and the `since` cursor is guarded by mtx. Returned
// values are defensive copies so callers can mutate them without corrupting the cache.
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

// ListAllRuleGroups implements RuleStore.
//
// It performs an incremental fetch against the configs service using the cached `since`
// cursor, merges the result into the cache under mtx, and returns a deep copy so callers
// can safely mutate the returned map and its slices.
func (c *ConfigRuleStore) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
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
		if cfg.IsDeleted() {
			delete(c.ruleGroupList, user)
			continue
		}
		rMap, err := cfg.Config.ParseFormatted()
		if err != nil {
			return nil, err
		}
		userRules := rulespb.RuleGroupList{}
		for file, rgs := range rMap {
			for _, rg := range rgs.Groups {
				userRules = append(userRules, rulespb.ToProto(user, file, rg))
			}
		}
		c.ruleGroupList[user] = userRules
	}

	c.since = getLatestConfigID(configs, c.since)

	// Return a deep copy so callers (e.g. Ruler.listRules deleting map keys, or
	// ListRuleGroupsForUserAndNamespace filtering by namespace) cannot corrupt the
	// shared cache. GetRules is incremental, so any corruption of the cached backing
	// array would otherwise be sticky until process restart.
	out := make(map[string]rulespb.RuleGroupList, len(c.ruleGroupList))
	for u, l := range c.ruleGroupList {
		out[u] = append(rulespb.RuleGroupList(nil), l...)
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
	all, err := c.ListAllRuleGroups(ctx)
	if err != nil {
		return nil, err
	}

	if namespace == "" {
		return all[userID], nil
	}

	// Build a NEW slice instead of filtering in place: the previous
	// `append(list[:ix], list[ix+1:]...)` loop shifts elements inside the backing array,
	// which would corrupt the cached slice if the returned map ever aliased the cache
	// again. Returning a fresh slice is also cheaper than repeated copy-down shifts.
	filtered := rulespb.RuleGroupList{}
	for _, g := range all[userID] {
		if g.GetNamespace() == namespace {
			filtered = append(filtered, g)
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
