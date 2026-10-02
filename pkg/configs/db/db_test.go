package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestConfig_MarshalYAML_RedactsInlinePassword asserts that a URI containing a
// password never appears in the YAML output used by the /config endpoint.
func TestConfig_MarshalYAML_RedactsInlinePassword(t *testing.T) {
	const secret = "SuperSecret123"
	cfg := Config{
		URI:           "postgres://cortex:" + secret + "@127.0.0.1:5432/configs?sslmode=disable",
		MigrationsDir: "/migrations",
		PasswordFile:  "",
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal returned error: %v", err)
	}

	got := string(out)
	if strings.Contains(got, secret) {
		t.Fatalf("marshalled config leaked inline password: %s", got)
	}
	if !strings.Contains(got, "cortex:") {
		t.Fatalf("marshalled config lost the username component: %s", got)
	}
	if !strings.Contains(got, "127.0.0.1:5432/configs") {
		t.Fatalf("marshalled config lost the host/db component: %s", got)
	}
}

// TestConfig_MarshalYAML_PreservesURIWithoutPassword asserts that URIs that do
// not contain a password are passed through unchanged.
func TestConfig_MarshalYAML_PreservesURIWithoutPassword(t *testing.T) {
	cfg := Config{
		URI: "postgres://cortex@127.0.0.1:5432/configs?sslmode=disable",
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal returned error: %v", err)
	}
	if !strings.Contains(string(out), cfg.URI) {
		t.Fatalf("expected URI to be preserved, got: %s", string(out))
	}
}

// TestConfig_MarshalYAML_MemoryURI asserts that non-postgres URIs (e.g. memory://)
// remain parseable and are not altered.
func TestConfig_MarshalYAML_MemoryURI(t *testing.T) {
	cfg := Config{URI: "memory://"}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal returned error: %v", err)
	}
	if !strings.Contains(string(out), "memory://") {
		t.Fatalf("expected memory:// to be preserved, got: %s", string(out))
	}
}
