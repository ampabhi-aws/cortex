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
// The store caches the config service's state (`since` and `ruleGroupList`) across calls so that
// subsequent requests only have to fetch the delta of rules changed since the previous poll. The
// cache is shared across every goroutine that holds a reference to the store (the ruler sync loop
// runs `loadRulesConcurrency` workers, the `/ruler/rule_groups` handler fans out to
// `fetchRulesConcurrency` workers, and each `/api/v1/rules` request runs on its own HTTP
// goroutine), so all reads and writes of the cache must be serialized through `mtx`. The internal
// map is never returned directly to callers; `ListAllRuleGroups` always returns a shallow copy so
// callers can neither race on nor mutate the cache.
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

// ListAllRuleGroups implements RuleStore. It is safe to call concurrently from multiple
// goroutines; the shared `since` / `ruleGroupList` cache is protected by `c.mtx`, parsing is
// performed outside the lock to avoid serializing CPU work, and the returned map is a fresh copy
// of the cache so callers can mutate (or iterate) it without racing with the next poll.
func (c *ConfigRuleStore) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
	c.mtx.Lock()
	since := c.since
	c.mtx.Unlock()

	// The network call to the config service must happen outside the lock so that a slow
	// configs backend cannot block every other caller of the store.
	configs, err := c.configClient.GetRules(ctx, since)
	if err != nil {
		return nil, err
	}

	// Parse into local state only; do not touch c.ruleGroupList until we re-acquire the lock.
	parsed := make(map[string]rulespb.RuleGroupList, len(configs))
	deleted := make([]string, 0, len(configs))
	for user, cfg := range configs {
		if cfg.IsDeleted() {
			deleted = append(deleted, user)
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
		parsed[user] = userRules
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	for _, u := range deleted {
		delete(c.ruleGroupList, u)
	}
	for u, rs := range parsed {
		c.ruleGroupList[u] = rs
	}
	c.since = getLatestConfigID(configs, c.since)

	// Return a shallow copy so callers can neither race on nor mutate the cache. The
	// RuleGroupList slices are cloned (append onto a nil slice) so that caller-side mutations
	// (e.g. the ruler's allowed-tenants filtering) cannot corrupt the shared cache either.
	out := make(map[string]rulespb.RuleGroupList, len(c.ruleGroupList))
	for u, rs := range c.ruleGroupList {
		out[u] = append(rulespb.RuleGroupList(nil), rs...)
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

	if namespace == "" {
		return r[userID], nil
	}

	list := r[userID]
	for ix := 0; ix < len(list); {
		if list[ix].GetNamespace() != namespace {
			list = append(list[:ix], list[ix+1:]...)
		} else {
			ix++
		}
	}

	return list, nil
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
