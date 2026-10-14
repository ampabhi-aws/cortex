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

// ConfigRuleStore is a concrete implementation of RuleStore that sources rules from the config service
type ConfigRuleStore struct {
	configClient client.Client

	// mtx guards concurrent access to since and ruleGroupList. ListAllRuleGroups
	// is invoked from many goroutines at once (up to fetchRulesConcurrency from
	// the ruler HTTP handlers plus the background rule-sync loop), so the shared
	// cache state must be synchronised.
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

// ListAllRuleGroups implements RuleStore. It refreshes the internal cache from
// the config service and returns a snapshot (fresh outer map and per-user slice
// copies) so callers cannot mutate the cached state held by the ruler.
func (c *ConfigRuleStore) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	configs, err := c.configClient.GetRules(ctx, c.since)

	if err != nil {
		return nil, err
	}

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

	c.since = getLatestConfigID(configs, c.since)

	// Return a defensive copy so callers (e.g. Ruler.listRules which deletes
	// disallowed tenants from the returned map) cannot mutate the cache.
	out := make(map[string]rulespb.RuleGroupList, len(c.ruleGroupList))
	for user, list := range c.ruleGroupList {
		copied := make(rulespb.RuleGroupList, len(list))
		copy(copied, list)
		out[user] = copied
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

	// r is already a defensive copy returned by ListAllRuleGroups, so we can
	// safely hand its per-user slice back without aliasing the cache.
	if namespace == "" {
		return r[userID], nil
	}

	// Build a new slice instead of filtering in place. Filtering in place with
	// append(list[:ix], list[ix+1:]...) would rewrite the backing array shared
	// with the cached entry and silently drop/duplicate rule groups across
	// subsequent sync cycles.
	list := r[userID]
	out := make(rulespb.RuleGroupList, 0, len(list))
	for _, g := range list {
		if g.GetNamespace() == namespace {
			out = append(out, g)
		}
	}

	return out, nil
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
