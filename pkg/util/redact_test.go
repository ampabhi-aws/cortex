package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

func TestRedactURLCredentials(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{"", ""},
		{"postgres://user:pw@host/db", "postgres://xxxxx:xxxxx@host/db"},
		{"postgres://host/db", "postgres://host/db"},
		{"http://u:p@a/x,http://b/x", "http://xxxxx:xxxxx@a/x,http://b/x"},
		{"not a url", "not a url"},
		{"https://marco:hunter2@alertmanager/am", "https://xxxxx:xxxxx@alertmanager/am"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, RedactURLCredentials(tc.in), "input %q", tc.in)
	}
}

func TestRedactYAMLConfig_RedactsCredentialKeys(t *testing.T) {
	type Nested struct {
		Password string `yaml:"password"`
		Token    string `yaml:"token"`
		Normal   string `yaml:"normal"`
	}
	type Outer struct {
		BasicAuthPassword string `yaml:"basic_auth_password"`
		AccessKeyID       string `yaml:"access_key_id"`
		KMSKeyID          string `yaml:"kms_key_id"`
		DatabaseURI       string `yaml:"uri"`
		AlertmanagerURL   string `yaml:"alertmanager_url"`
		Nested            Nested `yaml:"nested"`
	}
	in := Outer{
		BasicAuthPassword: "hunter2",
		AccessKeyID:       "AKIA123",
		KMSKeyID:          "kms-abc",
		DatabaseURI:       "postgres://u:p@h/db",
		AlertmanagerURL:   "http://marco:hunter2@am/am",
		Nested: Nested{
			Password: "sekret",
			Token:    "tok",
			Normal:   "visible",
		},
	}
	out, err := RedactYAMLConfig(in)
	require.NoError(t, err)
	data, err := yaml.Marshal(out)
	require.NoError(t, err)
	rendered := string(data)

	// Secrets are masked.
	assert.NotContains(t, rendered, "hunter2")
	assert.NotContains(t, rendered, "sekret")
	assert.NotContains(t, rendered, "p@h")
	assert.Contains(t, rendered, "********")
	assert.Contains(t, rendered, "xxxxx:xxxxx@h/db")
	assert.Contains(t, rendered, "xxxxx:xxxxx@am/am")

	// Public identifiers are preserved.
	assert.Contains(t, rendered, "AKIA123")
	assert.Contains(t, rendered, "kms-abc")
	assert.Contains(t, rendered, "visible")
}

func TestRedactYAMLConfig_PreservesStructure(t *testing.T) {
	in := map[string]interface{}{
		"a":        1,
		"password": "x",
		"nested": map[string]interface{}{
			"deep_password": "y",
			"list":          []interface{}{"a", "b"},
		},
	}
	out, err := RedactYAMLConfig(in)
	require.NoError(t, err)
	m, ok := out.(map[interface{}]interface{})
	require.True(t, ok, "expected map, got %T", out)
	assert.Equal(t, 1, m["a"])
	assert.Equal(t, MaskedPlaceholder, m["password"])
	nested, ok := m["nested"].(map[interface{}]interface{})
	require.True(t, ok)
	assert.Equal(t, MaskedPlaceholder, nested["deep_password"])
}
