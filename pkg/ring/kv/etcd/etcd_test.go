package etcd

import (
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfig_Password_IsMaskedInYAML ensures that an etcd client Config's
// Password is never emitted as cleartext when the whole Cortex config tree is
// serialised (for example by the unauthenticated GET /config endpoint).
func TestConfig_Password_IsMaskedInYAML(t *testing.T) {
	cfg := Config{
		UserName: "etcd-user",
		Password: flagext.Secret{Value: "super-secret-etcd-password"},
	}

	out, err := yaml.Marshal(&cfg)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "super-secret-etcd-password",
		"etcd password must not appear in cleartext in marshalled YAML; got:\n%s", string(out))
	assert.Contains(t, string(out), "password: '********'",
		"etcd password must be rendered as the masked token; got:\n%s", string(out))
}

// TestConfig_Password_FlagParses verifies the password flag still accepts a
// value and populates the underlying Secret.Value, preserving the pre-existing
// CLI contract.
func TestConfig_Password_FlagParses(t *testing.T) {
	var cfg Config
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlagsWithPrefix(fs, "")

	require.NoError(t, fs.Parse([]string{
		"-etcd.username=alice",
		"-etcd.password=some-pass",
	}))

	assert.Equal(t, "alice", cfg.UserName)
	assert.Equal(t, "some-pass", cfg.Password.Value)
}

// TestConfig_Password_UnmarshalYAML verifies that reading back a YAML config
// still populates the Secret value as before.
func TestConfig_Password_UnmarshalYAML(t *testing.T) {
	input := strings.Join([]string{
		"username: alice",
		"password: some-pass",
	}, "\n")

	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(input), &cfg))

	assert.Equal(t, "alice", cfg.UserName)
	assert.Equal(t, "some-pass", cfg.Password.Value)
}
