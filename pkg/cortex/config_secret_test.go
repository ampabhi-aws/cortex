package cortex

import (
	"flag"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// TestConfigYAMLDoesNotLeakSecrets guards against future plain-string
// credential fields in the Cortex Config. The /config HTTP endpoint
// yaml-marshals the whole top-level config, so any field whose yaml
// name looks like a credential must be typed flagext.Secret (or a
// similarly redacting type) so that MarshalYAML returns the standard
// mask. The test seeds every eligible flag with a sentinel value and
// fails if the sentinel then appears under a credential-looking key.
func TestConfigYAMLDoesNotLeakSecrets(t *testing.T) {
	const sentinel = "SENTINELVALUE123"

	cfg := &Config{}
	fs := flag.NewFlagSet("cortex-secret-test", flag.PanicOnError)
	cfg.RegisterFlags(fs)

	fs.VisitAll(func(f *flag.Flag) {
		if looksLikeSecret(f.Name) {
			_ = f.Value.Set(sentinel)
		}
	})

	assertNoCleartextSecrets(t, cfg, sentinel)
}

// secretKeyPattern matches YAML keys that are expected to be redacted
// in the marshalled /config response. The test only inspects fields
// whose key matches this pattern.
var secretKeyPattern = regexp.MustCompile(
	`(?i)(^|_)(password|secret)($|_)` +
		`|(^|_)(access|api|private|signing|encryption|auth)_?key($|_)` +
		`|(^|_)token($)` +
		`|(^|_)acl_token($|_)` +
		`|basic_auth_password` +
		`|service_account` +
		`|secret_access_key` +
		`|account_key`,
)

// pathLikeExclusions names fields whose name happens to contain a
// credential keyword but which only hold a filesystem path or a non-
// secret identifier. They must be ignored by both the seed step and
// the leak check.
var pathLikeExclusions = []string{
	"password_file",
	"access_key_id",
	"api_key_id",
	"token_file",
	"token_file_path",
	"tokens_file_path",
}

func isPathLikeExclusion(key string) bool {
	k := strings.ToLower(key)
	k = strings.ReplaceAll(k, "-", "_")
	k = strings.ReplaceAll(k, ".", "_")
	for _, suffix := range pathLikeExclusions {
		if k == suffix || strings.HasSuffix(k, "_"+suffix) || strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

func looksLikeSecret(name string) bool {
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "-", "_")
	n = strings.ReplaceAll(n, ".", "_")
	if isPathLikeExclusion(n) {
		return false
	}
	if strings.HasSuffix(n, "database_uri") {
		return true
	}
	return secretKeyPattern.MatchString(n)
}

func assertNoCleartextSecrets(t *testing.T, cfg interface{}, sentinel string) {
	t.Helper()

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "failed to marshal config")

	var tree map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &tree), "failed to re-unmarshal config")

	leaks := findSecretLeaks("", tree, sentinel)
	if len(leaks) > 0 {
		t.Fatalf("YAML-marshalled config leaks credential fields in cleartext "+
			"(each path below is a plain Go string instead of flagext.Secret); "+
			"change the field type and flag registration to flagext.Secret / f.Var:\n  %s",
			strings.Join(leaks, "\n  "))
	}
}

func findSecretLeaks(prefix string, node interface{}, sentinel string) []string {
	var leaks []string

	switch v := node.(type) {
	case map[string]interface{}:
		for k, child := range v {
			leaks = append(leaks, visitChild(prefix, k, child, sentinel)...)
		}
	case map[interface{}]interface{}:
		for rawKey, child := range v {
			ks, _ := rawKey.(string)
			leaks = append(leaks, visitChild(prefix, ks, child, sentinel)...)
		}
	case []interface{}:
		for _, item := range v {
			leaks = append(leaks, findSecretLeaks(prefix, item, sentinel)...)
		}
	}
	return leaks
}

func visitChild(prefix, key string, child interface{}, sentinel string) []string {
	path := key
	if prefix != "" {
		path = prefix + "." + key
	}
	var leaks []string
	if isSecretKey(key) && isCleartextSecretValue(child, sentinel) {
		leaks = append(leaks, path)
	}
	leaks = append(leaks, findSecretLeaks(path, child, sentinel)...)
	return leaks
}

func isSecretKey(key string) bool {
	if key == "" {
		return false
	}
	if isPathLikeExclusion(key) {
		return false
	}
	if key == "uri" {
		return true
	}
	return secretKeyPattern.MatchString(key)
}

func isCleartextSecretValue(v interface{}, sentinel string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if s == "" {
		return false
	}
	if s == strings.Repeat("*", 8) {
		return false
	}
	return strings.Contains(s, sentinel)
}
