package ruler

import (
	"crypto/md5"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
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
	err := m.FS.MkdirAll(path, 0777)
	if err != nil {
		return false, nil, err
	}

	// write all rule configs to disk
	for filename, groups := range ruleConfigs {
		// Store the encoded file name to better handle `/` characters
		encodedFileName := url.PathEscape(filename)

		// url.PathEscape does not escape `.`, so a namespace of "", "." or ".."
		// would collapse through filepath.Join onto the tenant's rules directory
		// (or the shared rules root) and the subsequent read/write would fail with
		// EISDIR, aborting the whole MapRules call before manager.Update is
		// reached. Skip these namespaces (log loudly) rather than let a single
		// malformed group permanently break the tenant's rule sync.
		if encodedFileName == "" || encodedFileName == "." || encodedFileName == ".." {
			level.Warn(m.logger).Log("msg", "skipping rule group with invalid namespace", "user", user, "namespace", filename)
			continue
		}
		fullFileName := filepath.Join(path, encodedFileName)
		// Defence in depth: make sure the computed target is a direct child of the
		// tenant directory. Any name that canonicalises away through filepath.Join
		// (e.g. embedded separators that slip past PathEscape in a future stdlib
		// change) is rejected here instead of silently rewriting the parent.
		if filepath.Dir(fullFileName) != path {
			level.Warn(m.logger).Log("msg", "skipping rule group whose encoded namespace is not a safe single path segment", "user", user, "namespace", filename, "encoded", encodedFileName)
			continue
		}

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

	info, err := m.FS.Stat(filename)
	if err == nil {
		// Ensure the existing path really is a regular file. If something has
		// placed a directory (or other non-regular entry) at the target path we
		// must not try to ReadFile/WriteFile it -- that would fail with EISDIR on
		// every poll and abort the whole MapRules run.
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("rule file target %q is not a regular file", filename)
		}
		current, err := afero.ReadFile(m.FS, filename)
		if err != nil {
			return false, err
		}
		newHash := md5.New()
		currentHash := md5.New()

		// bailout if there is no update
		if string(currentHash.Sum(current)) == string(newHash.Sum(d)) {
			return false, nil
		}
	}

	level.Info(m.logger).Log("msg", "updating rule file", "file", filename)
	err = afero.WriteFile(m.FS, filename, d, 0777)
	if err != nil {
		return false, err
	}

	return true, nil
}
