package cortex

import (
	"flag"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// TestConfigYAMLRedactsSecrets is a regression test for the information-disclosure
// bug where the Cortex GET /config endpoint rendered plaintext credentials for the
// Swift password, etcd username/password, ruler Alertmanager basic-auth password,
// and configs database URI. It walks the YAML representation of a fully-populated
// cortex.Config and asserts that every leaf whose field name or YAML key suggests
// it holds a secret is either empty or redacted. Any field whose type is a plain
// string tagged with a sensitive name will fail the assertion so that new
// deviations from the flagext.Secret / flagext.URLValue pattern cannot be
// introduced silently.
func TestConfigYAMLRedactsSecrets(t *testing.T) {
	cfg := &Config{}
	registerDummyFlags(t, cfg)

	// Populate every reachable string-typed field with a recognisable sentinel so
	// that if a credential is ever written out unredacted we would see the
	// sentinel in the marshalled YAML.
	populateStrings(reflect.ValueOf(cfg), "GREENSENTINELXYZ")

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	secretKey := regexp.MustCompile("(?i)(password|secret|token|api_key|accesskey|_key$|^key$|uri$)")

	for i, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")
		if !secretKey.MatchString(key) {
			continue
		}
		if val == "" || val == "********" {
			continue
		}
		// For URL-valued fields the masked form is postgres://user:********@host/db.
		if strings.Contains(val, "://") && strings.Contains(val, "********") {
			continue
		}
		if strings.Contains(val, "GREENSENTINELXYZ") {
			t.Fatalf("line %d: suspected secret field %q leaked the sentinel (full line: %q); the field is not using flagext.Secret / flagext.URLValue", i+1, key, line)
		}
		t.Fatalf("line %d: suspected secret field %q rendered with non-redacted value %q (full line: %q)", i+1, key, val, line)
	}
}

// registerDummyFlags runs RegisterFlags on cfg with a fresh FlagSet so defaults
// (e.g. the configs database URI) are applied, exactly like a real cortex binary.
func registerDummyFlags(t *testing.T, cfg *Config) {
	t.Helper()
	defer func() {
		// A few subsystems panic without extra wiring; ignore any such panic so
		// that this regression test stays focused on YAML redaction.
		_ = recover()
	}()
	fs := flag.NewFlagSet("redact-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg.RegisterFlags(fs)
}

// populateStrings recursively assigns the sentinel to every settable string
// field. It still recurses into flagext.Secret / flagext.URLValue values so
// their internal string fields get the sentinel - that way, if their custom
// MarshalYAML is removed or bypassed, the sentinel would leak and this test
// would fail.
func populateStrings(v reflect.Value, sentinel string) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return
		}
		populateStrings(v.Elem(), sentinel)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue
			}
			populateStrings(f, sentinel)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			populateStrings(v.Index(i), sentinel)
		}
	case reflect.Map:
		return
	case reflect.String:
		if v.CanSet() && v.String() == "" {
			v.SetString(sentinel)
		}
	}
}
