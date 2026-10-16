package ruler

import (
	"crypto/md5"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

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

// safeRuleFilepath builds the on-disk rule file path for the given namespace
// (filename) inside the per-tenant directory `dir`, and verifies that the
// resolved absolute path stays within `dir`. This is a defence-in-depth check
// against path-traversal via namespace names (e.g. `.` or `..`) that
// `url.PathEscape` does not neutralise, mirroring the pattern used by
// `safeTemplateFilepath` in pkg/alertmanager/multitenant.go.
func safeRuleFilepath(dir, filename string) (string, error) {
	// Reject explicit dot-segments. `url.PathEscape` does *not* escape '.',
	// so namespaces of "." or ".." would otherwise resolve to (or outside)
	// the per-tenant directory via filepath.Join. Path separators themselves
	// are escaped by url.PathEscape, so legitimate namespaces that contain
	// '/' are still accepted here and the containment check below enforces
	// the final boundary.
	if filename == "." || filename == ".." {
		return "", fmt.Errorf("invalid rule namespace %q: must not be '.' or '..'", filename)
	}

	containerDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	encodedFileName := url.PathEscape(filename)
	actualPath, err := filepath.Abs(filepath.Join(containerDir, encodedFileName))
	if err != nil {
		return "", err
	}

	// Ensure the resolved path is strictly inside the per-tenant directory.
	if actualPath == containerDir || !strings.HasPrefix(actualPath, containerDir+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid rule namespace %q: resolved filepath escapes the per-tenant rule directory", filename)
	}

	return actualPath, nil
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
		// Resolve and validate the on-disk filename. If a single namespace is
		// malformed (for example, the dot-segments `.` or `..` that
		// `url.PathEscape` does not neutralise), skip it and continue with the
		// rest so that one bad namespace cannot freeze the entire tenant sync.
		fullFileName, err := safeRuleFilepath(path, filename)
		if err != nil {
			level.Warn(m.logger).Log("msg", "skipping rule namespace with unsafe name", "user", user, "namespace", filename, "err", err)
			continue
		}

		fileUpdated, err := m.writeRuleGroupsIfNewer(groups, fullFileName)
		if err != nil {
			level.Warn(m.logger).Log("msg", "unable to write rule file, skipping namespace", "user", user, "namespace", filename, "file", fullFileName, "err", err)
			continue
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
