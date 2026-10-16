package cortex

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	"github.com/cortexproject/cortex/pkg/ruler"
	"github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigMarshalMasksSensitiveFields guarantees the API /config dump
// cannot leak credentials in cleartext. It walks the full default Cortex
// configuration marshalled as YAML looking for any key whose name matches
// password/secret/token/apikey/api_key and asserts the value is either
// empty or redacted via flagext.Secret.MarshalYAML.
func TestConfigMarshalMasksSensitiveFields(t *testing.T) {
	cfg := newDefaultConfig()

	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password = flagext.Secret{Value: "etcd-password-should-not-leak"}
	cfg.Ruler.Notifier.BasicAuth.Password = flagext.Secret{Value: "am-password-should-not-leak"}
	cfg.BlocksStorage.Bucket.Swift.Password = flagext.Secret{Value: "swift-password-should-not-leak"}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "default config must marshal cleanly")

	marshalled := string(data)

	for _, seeded := range []string{
		"etcd-password-should-not-leak",
		"am-password-should-not-leak",
		"swift-password-should-not-leak",
	} {
		require.NotContains(t, marshalled, seeded, "cleartext credential leaked in /config YAML dump")
	}

	credentialKey := regexp.MustCompile(`(?i)(password|secret|token|apikey|api_key)`)
	ignoreKeys := map[string]struct{}{
		"password_file":        {},
		"client_secret_file":   {},
		"bearer_token_file":    {},
		"credentials_file":     {},
		"token_file":           {},
		"service_account_file": {},
		"num_tokens":           {}, // ring token count, not a credential
		"tokens_file_path":     {}, // on-disk ring-token cache path
	}

	redacted := "********"
	for _, line := range strings.Split(marshalled, "\n") {
		trimmed := strings.TrimLeft(line, " -\t")
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := trimmed[:colon]
		if !credentialKey.MatchString(key) {
			continue
		}
		if _, skip := ignoreKeys[key]; skip {
			continue
		}
		value := strings.TrimSpace(trimmed[colon+1:])
		value = strings.Trim(value, "\"'")

		if value == "" || value == redacted {
			continue
		}
		t.Errorf("credential-like field %q marshalled with cleartext value %q (line: %q)", key, value, line)
	}

	var _ flagext.Secret = etcd.Config{}.Password
	var _ flagext.Secret = util.BasicAuth{}.Password
	var _ flagext.Secret = swift.Config{}.Password
	var _ flagext.Secret = ruler.NotifierConfig{}.BasicAuth.Password
}
