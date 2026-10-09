package etcd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfig_PasswordIsRedactedOnYAMLMarshal is a regression test for the
// finding where etcd.Config.Password was stored as a plain string and
// therefore rendered verbatim by Cortex's unauthenticated GET /config endpoint.
// The password MUST be stored as flagext.Secret so that its MarshalYAML method
// redacts the value on every config dump.
func TestConfig_PasswordIsRedactedOnYAMLMarshal(t *testing.T) {
	const plaintext = "SecretEtcdPassword"
	const redacted = "********"

	cfg := Config{
		Endpoints: []string{"etcd-0.internal:2379"},
		UserName:  "cortex",
		Password:  flagext.Secret{Value: plaintext},
	}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	rendered := string(out)
	assert.NotContains(t, rendered, plaintext,
		"etcd password must not be rendered in cleartext when marshalled to YAML")
	assert.Contains(t, rendered, redacted,
		"etcd password must be redacted when marshalled to YAML")

	// Round-trip: unmarshal raw YAML (with the plaintext value) and verify we recover it on the typed field.
	var decoded Config
	raw := []byte("endpoints:\n- etcd-0.internal:2379\nusername: cortex\npassword: " + plaintext + "\n")
	require.NoError(t, yaml.Unmarshal(raw, &decoded))
	assert.Equal(t, plaintext, decoded.Password.Value)

	// Sanity: the password line itself must not expose the plaintext in any form.
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "password:") {
			assert.NotContains(t, line, plaintext)
		}
	}
}
