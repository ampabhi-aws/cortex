package ruler

import (
	"crypto/md5"
	"errors"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// errMapperEmptyUser is returned when the mapper is asked to operate on a path
// that collapses onto the shared rules root (e.g. an empty tenant ID).
var errMapperEmptyUser = errors.New("refusing to map rules for empty tenant ID")

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
	// Defense-in-depth: refuse to remove the shared rules root directory. An
	// empty (or path-collapsing) userID would make filepath.Join(m.Path, userID)
	// equal to the configured root path, which holds every tenant's rule
	// files. Tenant validation must reject empty tenant IDs before reaching
	// here; this guards against regressions.
	if filepath.Clean(dirPath) == filepath.Clean(m.Path) {
		level.Error(m.logger).Log("msg", "refusing to remove shared rules root directory for empty tenant ID", "path", m.Path, "userID", userID)
		return
	}
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
	// Defense-in-depth: refuse to operate on the shared rules root. An empty
	// (or path-collapsing) user would make filepath.Join(m.Path, user) equal
	// to the configured root path, letting one tenant's rule files leak into
	// (and be deleted from) the shared directory holding every tenant's rules.
	if filepath.Clean(path) == filepath.Clean(m.Path) {
		level.Error(m.logger).Log("msg", "refusing to map rules onto shared rules root directory for empty tenant ID", "path", m.Path, "user", user)
		return false, nil, errMapperEmptyUser
	}
	err := m.FS.MkdirAll(path, 0777)
	if err != nil {
		return false, nil, err
	}

	// write all rule configs to disk
	for filename, groups := range ruleConfigs {
		// Store the encoded file name to better handle `/` characters
		encodedFileName := url.PathEscape(filename)
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

	_, err = m.FS.Stat(filename)
	if err == nil {
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
