package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestConfigMarshalYAMLRedactsURIUserinfo verifies that a password embedded in
// the configs.database.uri flag is not leaked when the Cortex config struct is
// serialised to YAML (e.g. by the unauthenticated /config endpoint).
func TestConfigMarshalYAMLRedactsURIUserinfo(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantURI string
	}{
		{
			name:    "no userinfo passes through",
			uri:     "postgres://configs-db.weave.local/configs?sslmode=require",
			wantURI: "postgres://configs-db.weave.local/configs?sslmode=require",
		},
		{
			name:    "username only is redacted",
			uri:     "postgres://postgres@configs-db.weave.local/configs?sslmode=disable",
			wantURI: "postgres://xxx@configs-db.weave.local/configs?sslmode=disable",
		},
		{
			name:    "username and password are redacted",
			uri:     "postgres://cortex:S3cretPass@configs-db/configs?sslmode=disable",
			wantURI: "postgres://xxx:xxx@configs-db/configs?sslmode=disable",
		},
		{
			name:    "memory scheme passes through",
			uri:     "memory://",
			wantURI: "memory://",
		},
		{
			name:    "empty uri passes through",
			uri:     "",
			wantURI: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{URI: tc.uri}
			out, err := yaml.Marshal(cfg)
			require.NoError(t, err)
			s := string(out)
			assert.Contains(t, s, "uri: "+quoteIfNeeded(tc.wantURI))
			if strings.Contains(tc.uri, "S3cretPass") {
				assert.NotContains(t, s, "S3cretPass")
			}
		})
	}
}

// quoteIfNeeded returns the YAML representation of a scalar string that these
// tests expect to see on the right-hand side of the "uri:" key.
func quoteIfNeeded(s string) string {
	if s == "" {
		return "\"\""
	}
	return s
}
