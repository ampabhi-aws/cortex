package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfigMarshalYAML_RedactsInlinePassword(t *testing.T) {
	cases := []struct {
		name       string
		uri        string
		wantURI    string
		wantNoPwd  string // substring that must NOT appear in the YAML output
	}{
		{
			name:    "inline user and password are redacted",
			uri:     "postgres://cortex:supersecret@db-host/configs?sslmode=disable",
			wantURI: "postgres://cortex:********@db-host/configs?sslmode=disable",
			wantNoPwd: "supersecret",
		},
		{
			name:    "no userinfo passes through",
			uri:     "postgres://db-host/configs?sslmode=disable",
			wantURI: "postgres://db-host/configs?sslmode=disable",
		},
		{
			name:    "username only passes through",
			uri:     "postgres://postgres@configs-db.weave.local/configs?sslmode=disable",
			wantURI: "postgres://postgres@configs-db.weave.local/configs?sslmode=disable",
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{URI: tc.uri}
			out, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			y := string(out)
			if tc.wantURI != "" && !strings.Contains(y, tc.wantURI) {
				t.Errorf("expected marshalled uri %q in output, got:\n%s", tc.wantURI, y)
			}
			if tc.wantNoPwd != "" && strings.Contains(y, tc.wantNoPwd) {
				t.Errorf("marshalled output must not contain password %q, got:\n%s", tc.wantNoPwd, y)
			}
			// Verify in-memory URI is unchanged (only wire representation is redacted).
			if cfg.URI != tc.uri {
				t.Errorf("in-memory URI mutated: got %q want %q", cfg.URI, tc.uri)
			}
		})
	}
}

func TestConfigUnmarshalYAML_RoundTrip(t *testing.T) {
	// Ensure default unmarshalling still works (no custom UnmarshalYAML added).
	in := []byte("uri: postgres://user:pw@h/db\nmigrations_dir: /m\npassword_file: /p\n")
	var cfg Config
	if err := yaml.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.URI != "postgres://user:pw@h/db" {
		t.Errorf("URI = %q", cfg.URI)
	}
	if cfg.MigrationsDir != "/m" {
		t.Errorf("MigrationsDir = %q", cfg.MigrationsDir)
	}
	if cfg.PasswordFile != "/p" {
		t.Errorf("PasswordFile = %q", cfg.PasswordFile)
	}
}
