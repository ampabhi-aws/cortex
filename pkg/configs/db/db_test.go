package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfigMarshalYAMLRedactsCredentials(t *testing.T) {
	cases := []struct {
		name     string
		uri      string
		mustHave string
		mustMiss string
	}{
		{
			name:     "password in userinfo is redacted",
			uri:      "postgres://configs_user:S3cret@db.internal/configs?sslmode=disable",
			mustHave: "configs_user",
			mustMiss: "S3cret",
		},
		{
			name:     "no userinfo is left unchanged",
			uri:      "postgres://db.internal/configs?sslmode=disable",
			mustHave: "db.internal/configs",
			mustMiss: "@",
		},
		{
			name:     "username-only userinfo is preserved",
			uri:      "postgres://postgres@configs-db.weave.local/configs?sslmode=disable",
			mustHave: "postgres@configs-db.weave.local",
			mustMiss: "xxxxx",
		},
		{
			name:     "memory scheme is unchanged",
			uri:      "memory://",
			mustHave: "memory://",
			mustMiss: "xxxxx",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{URI: tc.uri}
			out, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(out)
			if !strings.Contains(s, tc.mustHave) {
				t.Errorf("expected marshalled yaml %q to contain %q", s, tc.mustHave)
			}
			if tc.mustMiss != "" && strings.Contains(s, tc.mustMiss) {
				t.Errorf("expected marshalled yaml %q NOT to contain %q", s, tc.mustMiss)
			}
		})
	}
}
