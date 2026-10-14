package local

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	promRules "github.com/prometheus/prometheus/rules"

	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
)

const (
	Name = "local"
)

type Config struct {
	Directory string `yaml:"directory"`
}

// RegisterFlags registers flags.
func (cfg *Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.Directory, prefix+"local.directory", "", "Directory to scan for rules")
}

// Client expects to load already existing rules located at:
//
//	cfg.Directory / userID / namespace
type Client struct {
	cfg    Config
	loader promRules.GroupLoader
}

func NewLocalRulesClient(cfg Config, loader promRules.GroupLoader) (*Client, error) {
	if cfg.Directory == "" {
		return nil, errors.New("directory required for local rules config")
	}

	return &Client{
		cfg:    cfg,
		loader: loader,
	}, nil
}

func (l *Client) ListAllUsers(ctx context.Context) ([]string, error) {
	root := l.cfg.Directory
	infos, err := os.ReadDir(root)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read dir %s", root)
	}

	var result []string
	for _, info := range infos {
		// After resolving link, info.Name() may be different than user, so keep original name.
		user := info.Name()

		isDir := info.IsDir()
		if info.Type()&os.ModeSymlink != 0 {
			// os.ReadDir only returns result of LStat. Calling Stat resolves symlink.
			deRefInfo, err := os.Stat(filepath.Join(root, info.Name()))
			if err != nil {
				return nil, err
			}
			isDir = deRefInfo.IsDir()
		}

		if isDir {
			result = append(result, user)
		}
	}

	return result, nil
}

// ListAllRuleGroups implements rules.RuleStore. This method also loads the rules.
func (l *Client) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
	users, err := l.ListAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	lists := make(map[string]rulespb.RuleGroupList)
	for _, user := range users {
		list, err := l.loadAllRulesGroupsForUser(ctx, user)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list rule groups for user %s", user)
		}

		lists[user] = list
	}

	return lists, nil
}

// ListRuleGroupsForUserAndNamespace implements rules.RuleStore. This method also loads the rules.
func (l *Client) ListRuleGroupsForUserAndNamespace(ctx context.Context, userID string, namespace string) (rulespb.RuleGroupList, error) {
	if namespace != "" {
		return l.loadAllRulesGroupsForUserAndNamespace(ctx, userID, namespace)
	}

	return l.loadAllRulesGroupsForUser(ctx, userID)
}

func (l *Client) LoadRuleGroups(_ context.Context, _ map[string]rulespb.RuleGroupList) error {
	// This Client already loads the rules in its List methods, there is nothing left to do here.
	return nil
}

// GetRuleGroup implements RuleStore
func (l *Client) GetRuleGroup(ctx context.Context, userID, namespace, group string) (*rulespb.RuleGroupDesc, error) {
	return nil, errors.New("GetRuleGroup unsupported in rule local store")
}

// SetRuleGroup implements RuleStore
func (l *Client) SetRuleGroup(ctx context.Context, userID, namespace string, group *rulespb.RuleGroupDesc) error {
	return errors.New("SetRuleGroup unsupported in rule local store")
}

// DeleteRuleGroup implements RuleStore
func (l *Client) DeleteRuleGroup(ctx context.Context, userID, namespace string, group string) error {
	return errors.New("DeleteRuleGroup unsupported in rule local store")
}

// DeleteNamespace implements RulerStore
func (l *Client) DeleteNamespace(ctx context.Context, userID, namespace string) error {
	return errors.New("DeleteNamespace unsupported in rule local store")
}

func (l *Client) loadAllRulesGroupsForUser(ctx context.Context, userID string) (rulespb.RuleGroupList, error) {
	var allLists rulespb.RuleGroupList

	root := filepath.Join(l.cfg.Directory, userID)
	dirEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read rule dir %s", root)
	}

	for _, info := range dirEntries {
		// After resolving link, info.Name() may be different than namespace, so keep original name.
		namespace := info.Name()
		isDir := info.IsDir()

		if info.Type()&os.ModeSymlink != 0 {
			// os.ReadDir only returns result of LStat. Calling Stat resolves symlink.
			path := filepath.Join(root, info.Name())
			deRefInfo, err := os.Stat(path)
			if err != nil {
				return nil, errors.Wrapf(err, "unable to stat rule file %s", path)
			}
			isDir = deRefInfo.IsDir()
		}

		if isDir {
			continue
		}

		list, err := l.loadAllRulesGroupsForUserAndNamespace(ctx, userID, namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list rule group for user %s and namespace %s", userID, namespace)
		}

		allLists = append(allLists, list...)
	}

	return allLists, nil
}

func (l *Client) loadAllRulesGroupsForUserAndNamespace(_ context.Context, userID string, namespace string) (rulespb.RuleGroupList, error) {
	// Defense in depth: refuse any namespace that is not a single safe path
	// component so a traversal cannot escape the per-tenant directory even if
	// upstream validation is bypassed. The API layer
	// (pkg/ruler/api.go:parseNamespace) performs the same check; keeping it
	// here protects any other caller of the local rule store.
	if namespace == "" || namespace == "." || namespace == ".." ||
		strings.ContainsAny(namespace, "/\\\x00") {
		return nil, errors.New("invalid namespace")
	}

	userDir, err := filepath.Abs(filepath.Join(l.cfg.Directory, userID))
	if err != nil {
		return nil, errors.New("invalid rule store configuration")
	}
	filename, err := filepath.Abs(filepath.Join(userDir, namespace))
	if err != nil {
		return nil, errors.New("invalid namespace")
	}

	// Ensure the resolved rule file is still inside the per-tenant directory.
	// We require userDir to be a true path prefix (i.e. userDir + separator)
	// so that "<dir>/tenantA" cannot match "<dir>/tenantA-other". This mirrors
	// safeTemplateFilepath in the Alertmanager.
	sep := string(filepath.Separator)
	if filename != userDir && !strings.HasPrefix(filename, userDir+sep) {
		return nil, errors.New("invalid namespace")
	}

	rulegroups, allErrors := l.loader.Load(filename)
	if len(allErrors) > 0 {
		// Do not leak the resolved filesystem path or raw parse errors (which
		// may embed file content fragments) back to API callers.
		return nil, errors.Errorf("error parsing namespace %q", namespace)
	}

	var list rulespb.RuleGroupList

	for _, group := range rulegroups.Groups {
		desc := rulespb.ToProto(userID, namespace, group)
		list = append(list, desc)
	}

	return list, nil
}
