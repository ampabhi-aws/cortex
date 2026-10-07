package ruler

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

const (
	// ruleDirMode is the restrictive permission used for per-tenant rule
	// directories under -ruler.rule-path. Only the ruler process should be
	// able to read or write the materialised rule state, which is the
	// authoritative evaluation input passed to the per-tenant Prometheus
	// manager. -ruler.rule-path must be a private volume not shared with
	// other containers or local users.
	ruleDirMode os.FileMode = 0o700
	// ruleFileMode is the restrictive permission used for mapped rule
	// files. Rule files are evaluation input and must not be modifiable
	// by any other local principal.
	ruleFileMode os.FileMode = 0o600
)

// mapper is designed to enusre the provided rule sets are identical
// to the on-disk rules tracked by the prometheus manager
type mapper struct {
	Path string // Path specifies the directory in which rule files will be mapped.

	FS     afero.Fs
	logger log.Logger
}

func newMapper(path string, logger log.Logger) *mapper {
	m := &mapper{
		Path:   path,
		FS:     afero.NewOsFs(),
		logger: logger,
	}
	m.cleanup()

	return m
}

func (m *mapper) cleanupUser(userID string) {
	dirPath := filepath.Join(m.Path, userID)
	err := m.FS.RemoveAll(dirPath)
	if err != nil {
		level.Warn(m.logger).Log("msg", "unable to remove user directory", "path", dirPath, "err", err)
	}
}

// cleanup removes all of the user directories in the path of the mapper
func (m *mapper) cleanup() {
	level.Info(m.logger).Log("msg", "cleaning up mapped rules directory", "path", m.Path)

	users, err := m.users()
	if err != nil {
		level.Error(m.logger).Log("msg", "unable to read rules directory", "path", m.Path, "err", err)
		return
	}

	for _, u := range users {
		m.cleanupUser(u)
	}
}

func (m *mapper) users() ([]string, error) {
	var result []string

	dirs, err := afero.ReadDir(m.FS, m.Path)
	for _, u := range dirs {
		if u.IsDir() {
			result = append(result, u.Name())
		}
	}

	return result, err
}

func (m *mapper) MapRules(user string, ruleConfigs map[string][]rulefmt.RuleGroup) (bool, []string, error) {
	anyUpdated := false
	filenames := []string{}

	// user rule files will be stored as `/<path>/<userid>/<encoded filename>`
	path := filepath.Join(m.Path, user)
	if err := m.FS.MkdirAll(path, ruleDirMode); err != nil {
		return false, nil, err
	}
	// MkdirAll does not chmod pre-existing directories, and a fresh
	// directory's effective mode depends on the process umask; enforce the
	// restrictive mode explicitly so the rule state is never writable by
	// other local principals.
	if err := m.FS.Chmod(path, ruleDirMode); err != nil {
		return false, nil, err
	}

	// write all rule configs to disk
	for filename, groups := range ruleConfigs {
		// Store the encoded file name to better handle `/` characters
		encodedFileName := url.PathEscape(filename)

		// Reject namespaces that are not a single safe filename. url.PathEscape
		// leaves `.` and `..` untouched, which would collapse the mapped file
		// onto an existing directory and silently break the tenant's rule
		// sync; `/` and `\\` would allow escaping the per-tenant directory.
		if encodedFileName == "" || encodedFileName == "." || encodedFileName == ".." ||
			strings.ContainsAny(encodedFileName, `/\`) {
			return false, nil, fmt.Errorf("invalid namespace %q", filename)
		}

		fullFileName := filepath.Join(path, encodedFileName)

		fileUpdated, err := m.writeRuleGroupsIfNewer(groups, fullFileName)
		if err != nil {
			return false, nil, err
		}
		filenames = append(filenames, fullFileName)
		anyUpdated = anyUpdated || fileUpdated
	}

	// and clean any up that shouldn't exist
	existingFiles, err := afero.ReadDir(m.FS, path)
	if err != nil {
		return false, nil, err
	}

	for _, existingFile := range existingFiles {
		fullFileName := filepath.Join(path, existingFile.Name())

		// Ensure the namespace is decoded from a url path encoding to see if it is still required
		decodedNamespace, err := url.PathUnescape(existingFile.Name())
		if err != nil {
			level.Warn(m.logger).Log("msg", "unable to remove rule file on disk", "file", fullFileName, "err", err)
			continue
		}

		ruleGroups := ruleConfigs[string(decodedNamespace)]

		if ruleGroups == nil {
			err = m.FS.Remove(fullFileName)
			if err != nil {
				level.Warn(m.logger).Log("msg", "unable to remove rule file on disk", "file", fullFileName, "err", err)
			}
			anyUpdated = true
		}
	}

	return anyUpdated, filenames, nil
}

func (m *mapper) writeRuleGroupsIfNewer(groups []rulefmt.RuleGroup, filename string) (bool, error) {
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Name > groups[j].Name
	})

	rgs := rulefmt.RuleGroups{Groups: groups}

	d, err := yaml.Marshal(&rgs)
	if err != nil {
		return false, err
	}

	// Bail out if the current file contents are byte-identical to what we
	// would write. The previous implementation combined two md5.New().Sum(x)
	// calls, which prepend x to an empty digest rather than hashing it, so
	// the short-circuit only fired when the raw bytes were already equal.
	// Compare the raw bytes directly to keep that (correct) behaviour
	// explicit and avoid the misleading hash dance.
	if cur, err := afero.ReadFile(m.FS, filename); err == nil && bytes.Equal(cur, d) {
		return false, nil
	}

	level.Info(m.logger).Log("msg", "updating rule file", "file", filename)
	if err := afero.WriteFile(m.FS, filename, d, ruleFileMode); err != nil {
		return false, err
	}

	return true, nil
}
