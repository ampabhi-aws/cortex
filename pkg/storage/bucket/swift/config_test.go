package swift

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// TestConfig_PasswordMasked ensures that the Swift object-storage password
// is never emitted in cleartext when the Config struct is YAML-marshaled.
// The /config HTTP endpoint renders the live config via yaml.Marshal, so the
// password type must be a masking type (flagext.Secret).
func TestConfig_PasswordMasked(t *testing.T) {
	const plaintext = "super-secret-swift-password"

	cfg := Config{}
	require.NoError(t, cfg.Password.Set(plaintext))

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	assert.NotContains(t, string(out), plaintext, "swift password must not appear in cleartext in YAML output")
	assert.Contains(t, string(out), "********", "swift password must be masked in YAML output")
}

// TestConfig_PasswordEmptyNotMasked verifies that an unset password is not
// masked (otherwise diffs against the default would always show a value).
func TestConfig_PasswordEmptyNotMasked(t *testing.T) {
	cfg := Config{}
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "********", "empty swift password must not render as masked")
}

// TestConfig_PasswordRoundTrip asserts that YAML unmarshaling populates the
// Password.Value field (the masking type must still accept input).
func TestConfig_PasswordRoundTrip(t *testing.T) {
	const plaintext = "another-secret"
	in := "password: " + plaintext + "\n"
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(in), &cfg))
	assert.Equal(t, plaintext, cfg.Password.Value)
	// Guard: direct string check on the marshalled form must not leak.
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(out), plaintext), "round-tripped password leaked in marshaled YAML")
}
