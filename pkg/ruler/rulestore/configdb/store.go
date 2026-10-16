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

	// mtx guards the mutable cache fields (since, ruleGroupList) because
	// a single ConfigRuleStore instance is shared by the ruler sync loop
	// and by multiple HTTP handler goroutines (including the 16-way
	// fan-out in Ruler.ListAllRules). Without this lock, concurrent
	// callers would race on the map writes and trigger Go's unrecoverable
	// "concurrent map writes" fatal error.
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

// ListAllRuleGroups implements RuleStore. The returned map is a freshly
// allocated snapshot of the cache; callers may safely mutate it without
// affecting the shared cache. The inner RuleGroupList slices are also
// freshly allocated so callers may not accidentally corrupt the cached
// backing arrays (e.g. with in-place slice filtering).
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

	// Return a deep copy of the cache so callers cannot mutate the
	// shared map or the per-user slices.
	out := make(map[string]rulespb.RuleGroupList, len(c.ruleGroupList))
	for user, groups := range c.ruleGroupList {
		if len(groups) == 0 {
			out[user] = rulespb.RuleGroupList{}
			continue
		}
		cp := make(rulespb.RuleGroupList, len(groups))
		copy(cp, groups)
		out[user] = cp
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

	// r is already a deep-copy snapshot from ListAllRuleGroups, so it is
	// safe to return r[userID] directly or filter it without affecting
	// the shared cache. We still build a freshly allocated slice for the
	// namespace-filtered case to make the no-aliasing guarantee explicit
	// and avoid any accidental coupling to the snapshot's backing array.
	if namespace == "" {
		return r[userID], nil
	}

	list := r[userID]
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
