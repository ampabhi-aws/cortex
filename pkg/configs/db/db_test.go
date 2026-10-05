package db

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfig_MarshalYAML_RedactsURI(t *testing.T) {
	cfg := Config{URI: "postgres://u:p@h/db"}
	v, err := cfg.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "u:xxxxx@h/db") {
		t.Fatalf("expected redacted URI in output; got %s", s)
	}
	if strings.Contains(s, "u:p@h/db") {
		t.Fatalf("secret leaked in output: %s", s)
	}
}

func TestConfig_MarshalYAML_PreservesURIWithoutPassword(t *testing.T) {
	cfg := Config{URI: "postgres://u@h/db"}
	v, err := cfg.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "postgres://u@h/db") {
		t.Fatalf("expected URI to be preserved; got %s", s)
	}
}
