package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfig_MarshalYAML_RedactsPassword(t *testing.T) {
	cfg := Config{
		URI:           "postgres://cortex:s3cr3t@configs-db/configs?sslmode=disable",
		MigrationsDir: "/migrations",
		PasswordFile:  "",
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "s3cr3t") {
		t.Fatalf("marshalled YAML leaked password: %s", s)
	}
	if !strings.Contains(s, "cortex:********@configs-db") {
		t.Fatalf("marshalled YAML did not mask password as expected: %s", s)
	}
}

func TestConfig_MarshalYAML_NoPasswordUnchanged(t *testing.T) {
	// Default DSN carries a username but no password; must round-trip unchanged.
	cfg := Config{URI: "postgres://postgres@configs-db.weave.local/configs?sslmode=disable"}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(out), "postgres://postgres@configs-db.weave.local/configs?sslmode=disable") {
		t.Fatalf("expected URI preserved when no password present, got: %s", string(out))
	}
}

func TestConfig_MarshalYAML_EmptyURI(t *testing.T) {
	cfg := Config{}
	if _, err := yaml.Marshal(cfg); err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
}
