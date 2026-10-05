package configdb

import (
	"context"
	"errors"

	"github.com/cortexproject/cortex/pkg/configs/client"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
)

const (
	Name = "configdb"
)

// ConfigRuleStore is a concrete implementation of RuleStore that sources rules from the config service
type ConfigRuleStore struct {
	configClient  client.Client
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

	return c.ruleGroupList, nil
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

	cached := r[userID]
	if namespace == "" {
		// Return a copy so callers cannot mutate the cached slice backing array.
		if cached == nil {
			return nil, nil
		}
		out := make(rulespb.RuleGroupList, len(cached))
		copy(out, cached)
		return out, nil
	}

	// Build a new slice containing only the matching namespace. Filtering with
	// the in-place `append(list[:ix], list[ix+1:]...)` idiom would mutate the
	// cached backing array that `ListAllRuleGroups` returns by reference,
	// permanently corrupting the tenant's cached rule groups (losing entries
	// from other namespaces and creating duplicates). See issue in
	// pkg/ruler/rulestore/configdb/store.go for details.
	out := make(rulespb.RuleGroupList, 0, len(cached))
	for _, rg := range cached {
		if rg.GetNamespace() == namespace {
			out = append(out, rg)
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
