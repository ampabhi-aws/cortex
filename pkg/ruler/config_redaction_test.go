package ruler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigMarshalYAMLRedactsSecrets verifies that marshalling a ruler.Config
// does not leak the Alertmanager basic-auth password or URL-embedded userinfo
// through endpoints like /config that YAML-marshal the running config.
func TestConfigMarshalYAMLRedactsSecrets(t *testing.T) {
	const secret = "s3cr3t-sentinel-value"

	cfg := Config{
		AlertmanagerURL: "https://ruler:" + secret + "@alertmanager.internal/alertmanager,http://plain.example/am",
		Notifier: NotifierConfig{
			BasicAuth: util.BasicAuth{
				Username: "ruler",
				Password: flagext.Secret{Value: secret},
			},
		},
	}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	rendered := string(out)

	require.NotContains(t, rendered, secret, "secret must not appear in marshalled config: %s", rendered)
	require.Contains(t, rendered, "basic_auth_password: \"********\"")
	// URL userinfo credentials must be stripped (parsed/replaced) in the marshalled URL.
	require.NotContains(t, rendered, "ruler:"+secret+"@")
	// URL without credentials is left untouched.
	require.Contains(t, rendered, "http://plain.example/am")
}

func TestRedactAlertmanagerURLUserinfo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"http://host/path", "http://host/path"},
		{"https://user:pass@host/path", "https://user:xxxxx@host/path"},
		{"https://user@host/path", "https://user@host/path"},
		{"https://a:b@h1,https://c:d@h2", "https://a:xxxxx@h1,https://c:xxxxx@h2"},
	}
	for _, c := range cases {
		got := redactAlertmanagerURLUserinfo(c.in)
		require.Equal(t, c.want, got, "input=%q", c.in)
	}
}

// TestBasicAuthSecretRedactedInYAML asserts util.BasicAuth, which is used only
// by the ruler, redacts the password on YAML marshal.
func TestBasicAuthSecretRedactedInYAML(t *testing.T) {
	const secret = "another-sentinel"
	ba := util.BasicAuth{Username: "u", Password: flagext.Secret{Value: secret}}
	out, err := yaml.Marshal(ba)
	require.NoError(t, err)
	s := string(out)
	require.False(t, strings.Contains(s, secret), "secret leaked: %s", s)
	require.Contains(t, s, "basic_auth_password: \"********\"")
}
