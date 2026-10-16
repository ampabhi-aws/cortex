package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfig_MarshalYAML_MasksURIPassword(t *testing.T) {
	cfg := Config{
		URI:           "postgres://cortex:S3cretPass@db-host/configs?sslmode=disable",
		MigrationsDir: "/migrations",
		PasswordFile:  "/etc/configs-db-password",
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "S3cretPass") {
		t.Fatalf("marshalled YAML must not contain the password; got:\n%s", s)
	}
	if !strings.Contains(s, "********") {
		t.Fatalf("marshalled YAML must contain the masked password placeholder; got:\n%s", s)
	}
	if !strings.Contains(s, "cortex:") {
		t.Fatalf("marshalled YAML should preserve the username; got:\n%s", s)
	}
	if !strings.Contains(s, "db-host") {
		t.Fatalf("marshalled YAML should preserve the host; got:\n%s", s)
	}
}

func TestConfig_MarshalYAML_PreservesURIWithoutPassword(t *testing.T) {
	cfg := Config{URI: "postgres://cortex@db-host/configs?sslmode=disable"}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "********") {
		t.Fatalf("URIs without an embedded password should not be masked; got:\n%s", s)
	}
	if !strings.Contains(s, "cortex@db-host") {
		t.Fatalf("username/host should be preserved; got:\n%s", s)
	}
}

func TestConfig_MarshalYAML_PreservesMemoryURI(t *testing.T) {
	cfg := Config{URI: "memory://"}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(out), "memory://") {
		t.Fatalf("memory:// URI should be preserved verbatim; got:\n%s", string(out))
	}
}

func TestConfig_RoundTripYAMLDoesNotOverwriteURIWithMask(t *testing.T) {
	// After unmarshalling a previously-marshalled (masked) YAML, the plain
	// URI field is simply the string that was emitted; this test documents
	// that behaviour so operators are aware that re-ingesting /config output
	// is not safe for round-tripping credentials (it also prevents the mask
	// from being leaked back into the live config via unmarshal).
	cfg := Config{URI: "postgres://cortex:S3cretPass@db-host/configs?sslmode=disable"}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	var round Config
	if err := yaml.Unmarshal(out, &round); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if strings.Contains(round.URI, "S3cretPass") {
		t.Fatalf("round-tripped URI should not contain the original password; got %q", round.URI)
	}
}
