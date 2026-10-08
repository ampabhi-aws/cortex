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

// maxEncodedFilenameLen bounds the on-disk length of the per-namespace rule
// file name. Common Linux filesystems cap each path component at 255 bytes
// (NAME_MAX); enforcing the bound after url.PathEscape (which may expand each
// byte up to three-fold) prevents one poisoned namespace from aborting the
// whole tenant's MapRules call with ENAMETOOLONG.
const maxEncodedFilenameLen = 255

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
	err := m.FS.MkdirAll(path, 0755)
	if err != nil {
		return false, nil, err
	}

	// write all rule configs to disk
	for filename, groups := range ruleConfigs {
		// Defense in depth: the API layer already rejects namespaces that are
		// unsafe to materialize as a filename, but the mapper is also used by
		// other call paths (e.g. loading from the object store at startup) so
		// we re-check here and skip (rather than abort) any namespace that
		// cannot be mapped. This prevents one bad object in the rule store
		// from disabling every rule for the tenant.
		if err := safeNamespaceForFilename(filename); err != nil {
			level.Warn(m.logger).Log("msg", "skipping namespace that cannot be mapped to a safe filename", "user", user, "namespace", filename, "err", err)
			continue
		}

		// Store the encoded file name to better handle `/` characters
		encodedFileName := url.PathEscape(filename)
		if len(encodedFileName) > maxEncodedFilenameLen {
			level.Warn(m.logger).Log("msg", "skipping namespace whose encoded filename exceeds the filesystem limit", "user", user, "namespace", filename, "encoded_len", len(encodedFileName), "limit", maxEncodedFilenameLen)
			continue
		}
		fullFileName := filepath.Join(path, encodedFileName)

		// Ensure the resulting path still lives inside the tenant directory.
		// This is belt-and-braces: url.PathEscape rewrites '/', and
		// safeNamespaceForFilename already rejects '.' / '..', but we assert
		// the invariant here as the last line of defense before touching the
		// filesystem.
		if filepath.Dir(fullFileName) != path {
			level.Warn(m.logger).Log("msg", "skipping namespace that resolves outside the tenant directory", "user", user, "namespace", filename, "resolved", fullFileName)
			continue
		}

		fileUpdated, err := m.writeRuleGroupsIfNewer(groups, fullFileName)
		if err != nil {
			// Do not abort the whole tenant's mapping on a single bad file;
			// log and continue so the remaining rule groups still get loaded.
			level.Error(m.logger).Log("msg", "unable to write rule file", "user", user, "namespace", filename, "file", fullFileName, "err", err)
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
	err = afero.WriteFile(m.FS, filename, d, 0644)
	if err != nil {
		return false, err
	}

	return true, nil
}

// safeNamespaceForFilename returns an error if the given namespace cannot be
// safely materialized as a single on-disk path component. It mirrors the
// validation applied at the HTTP API layer and exists as a defense in depth
// for namespaces loaded from the rule store (which may predate the API-level
// check or come from another process).
func safeNamespaceForFilename(namespace string) error {
	if namespace == "" {
		return fmt.Errorf("namespace must not be empty")
	}
	if namespace == "." || namespace == ".." {
		return fmt.Errorf("namespace %q collides with a special directory entry", namespace)
	}
	if strings.ContainsAny(namespace, "\\\x00") {
		return fmt.Errorf("namespace contains disallowed byte (backslash or NUL)")
	}
	return nil
}
