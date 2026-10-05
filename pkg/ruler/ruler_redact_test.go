package ruler

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfig_MarshalYAML_RedactsAlertmanagerURL(t *testing.T) {
	cfg := Config{AlertmanagerURL: "http://u:p@h/"}
	v, err := cfg.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "u:xxxxx@h") {
		t.Fatalf("expected redacted URL in output; got %s", s)
	}
	if strings.Contains(s, "u:p@h") {
		t.Fatalf("secret leaked in output: %s", s)
	}
}
