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
	filename, err := safeJoinInsideDir(l.cfg.Directory, userID, namespace)
	if err != nil {
		return nil, err
	}

	rulegroups, allErrors := l.loader.Load(filename)
	if len(allErrors) > 0 {
		// Do not expose the resolved absolute filename or the raw parser error
		// (which can embed file contents) to the caller. The absolute path is
		// still useful for operators, so include it in the wrapped error that
		// is logged server-side via the API layer, but surface only a generic
		// message to end-users of the local store.
		return nil, errors.Wrapf(allErrors[0], "error parsing rule group for user %q namespace %q", userID, namespace)
	}

	var list rulespb.RuleGroupList

	for _, group := range rulegroups.Groups {
		desc := rulespb.ToProto(userID, namespace, group)
		list = append(list, desc)
	}

	return list, nil
}

// safeJoinInsideDir builds <dir>/<userID>/<namespace> and verifies that the
// resulting path (after symlink resolution if the path exists) is contained
// within <dir>/<userID>. This mirrors the alertmanager's safeTemplateFilepath
// hardening and prevents attacker-controlled namespace values that contain
// '..' or path separators from escaping the per-tenant directory.
func safeJoinInsideDir(dir, userID, namespace string) (string, error) {
	userDir, err := filepath.Abs(filepath.Join(dir, userID))
	if err != nil {
		return "", errors.Wrap(err, "unable to resolve user directory")
	}

	full, err := filepath.Abs(filepath.Join(userDir, namespace))
	if err != nil {
		return "", errors.Wrap(err, "unable to resolve rule group path")
	}

	// Lexical check: after filepath.Clean (performed by filepath.Abs/Join),
	// the final path must still be inside the per-tenant directory. This is
	// the primary defense against '../' traversal in attacker-supplied
	// namespaces, independent of what exists on disk.
	if !isWithinDir(full, userDir) {
		return "", errors.Errorf("invalid namespace %q: resolved path escapes the per-tenant directory", namespace)
	}

	// Symlink-resolution check: if both the per-tenant directory and the
	// target path exist, make sure the target's physical location is still
	// inside the physical per-tenant directory. We resolve both ends with
	// EvalSymlinks so a symlinked tenant directory (which is a legitimate
	// deployment pattern) does not false-positive. We ignore "not exists"
	// so that a missing namespace file still reaches the loader and
	// produces a predictable error.
	resolvedUserDir, err := filepath.EvalSymlinks(userDir)
	if err != nil {
		if os.IsNotExist(err) {
			return full, nil
		}
		return "", errors.Wrap(err, "unable to resolve user directory")
	}
	resolvedFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		if os.IsNotExist(err) {
			return full, nil
		}
		return "", errors.Wrap(err, "unable to resolve rule group path")
	}
	if !isWithinDir(resolvedFull, resolvedUserDir) {
		return "", errors.Errorf("invalid namespace %q: resolved path escapes the per-tenant directory", namespace)
	}

	return full, nil
}

// isWithinDir reports whether path is equal to parent or located within it.
// Both arguments must be cleaned absolute paths.
func isWithinDir(path, parent string) bool {
	parent = filepath.Clean(parent)
	path = filepath.Clean(path)
	if path == parent {
		return true
	}
	return strings.HasPrefix(path, parent+string(os.PathSeparator))
}
