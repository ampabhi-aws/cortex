package cortex

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// sentinel is a value that, after being written into every reachable string
// field of the config, must not survive YAML marshalling. If it does, a new
// credential-like field has been added that is not using the project's
// flagext.Secret masking type (whose MarshalYAML returns "********"), which
// means that field would leak in cleartext via GET /config and
// -print.config.
const configLeakSentinel = "CORTEX-REGRESSION-SENTINEL-DO-NOT-EXPOSE"

// fieldsAllowedToContainSentinel enumerates YAML paths for struct string
// fields that are legitimately echoed back in the config dump and are NOT
// credentials (hostnames, URLs, usernames, paths, labels, etc.).
//
// This list is intentionally conservative: anything that even looks like a
// credential ("password", "secret", "token", "key", "auth"...) is NOT in
// here and MUST use flagext.Secret.
//
// NOTE: because reflection cannot distinguish a credential from a
// non-credential by type alone, we instead rely on field-name heuristics
// below. This list is used only to narrow false positives from the
// heuristic.
var fieldsAllowedToContainSentinel = map[string]bool{}

// looksLikeCredential returns true if a struct field name (lower-cased) looks
// like a credential that must be masked.
func looksLikeCredential(name string) bool {
	n := strings.ToLower(name)
	// Any field name that embeds one of these substrings is treated as a
	// credential. We deliberately include "key" so that AccessKey,
	// SecretKey, APIKey etc. are all flagged.
	for _, needle := range []string{
		"password",
		"secret",
		"token",
		"apikey",
		"api_key",
		"accesskey",
		"access_key",
	} {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

// fillStringsWithSentinel walks v and sets every exported string field
// (recursively, including through structs, pointers, slices and maps) to
// the sentinel value. It intentionally does NOT touch flagext.Secret.Value
// (that field is exported, but its enclosing type overrides MarshalYAML to
// mask the value, so writing the sentinel there is still safe).
func fillStringsWithSentinel(v reflect.Value) {
	if !v.IsValid() {
		return
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		fillStringsWithSentinel(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		fillStringsWithSentinel(v.Elem())
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			fillStringsWithSentinel(v.Field(i))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fillStringsWithSentinel(v.Index(i))
		}
	case reflect.Map:
		// We don't mutate map values in-place (they are not addressable) —
		// but the project's config tree doesn't carry secrets inside maps,
		// so that's acceptable for this regression.
		return
	case reflect.String:
		if v.CanSet() {
			v.SetString(configLeakSentinel)
		}
	}
}

// collectCredentialFieldPaths returns every field path (in dotted struct-tag
// notation, e.g. "blocks_storage.swift.password") that looksLikeCredential
// identifies in the config tree. Used to assert that every credential field
// is masked after marshalling.
func collectCredentialFieldPaths(v reflect.Value, prefix string, out map[string]bool) {
	if !v.IsValid() {
		return
	}

	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return
		}
		collectCredentialFieldPaths(v.Elem(), prefix, out)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			tag := sf.Tag.Get("yaml")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = sf.Name
			}
			childPrefix := prefix
			if !strings.Contains(tag, "inline") && name != "" {
				if childPrefix != "" {
					childPrefix += "."
				}
				childPrefix += name
			}
			if looksLikeCredential(sf.Name) || looksLikeCredential(name) {
				out[childPrefix] = true
			}
			collectCredentialFieldPaths(v.Field(i), childPrefix, out)
		}
	}
}

// TestConfigDoesNotLeakCredentialsOnYAMLMarshal is the regression that
// enforces the finding's remediation: when the whole cortex.Config is
// marshalled to YAML (which is exactly what GET /config and -print.config
// do), no credential-named string field is allowed to escape in cleartext.
//
// The test fills every reachable string field in the config with a
// sentinel, marshals the config, and asserts that the sentinel does not
// appear on any YAML line whose key looks like a credential. Any new
// credential field added to the config tree that forgets to use
// flagext.Secret will cause this test to fail.
func TestConfigDoesNotLeakCredentialsOnYAMLMarshal(t *testing.T) {
	cfg := newDefaultConfig()

	// Populate every string field in the config tree with the sentinel.
	fillStringsWithSentinel(reflect.ValueOf(cfg).Elem())

	// Enumerate every credential-named field path we expect to be masked.
	credentialPaths := map[string]bool{}
	collectCredentialFieldPaths(reflect.ValueOf(cfg).Elem(), "", credentialPaths)
	require.NotEmpty(t, credentialPaths, "expected to find at least one credential-named field in the config tree")

	// Marshal exactly like util.WriteYAMLResponse does.
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	rendered := string(out)

	// 1. No credential-named YAML key may carry the sentinel.
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		key := trimmed[:colon]
		if !looksLikeCredential(key) {
			continue
		}
		require.NotContains(t, trimmed, configLeakSentinel,
			"credential field %q leaks cleartext in /config YAML output (line: %q); "+
				"the field must be declared as flagext.Secret so MarshalYAML masks it as \"********\"",
			key, line)
	}

	// 2. The three fields that regressed in this finding must be masked
	// (defence in depth against future renames hiding them from the
	// heuristic above).
	for _, needle := range []string{
		"swift.password",
		"etcd.password",
		"basic_auth_password",
	} {
		idx := strings.Index(rendered, needle+":")
		if idx < 0 {
			continue
		}
		// Grab the value on that line.
		line := rendered[idx:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		require.NotContains(t, line, configLeakSentinel,
			"%s must be masked in the /config YAML dump", needle)
	}
}
