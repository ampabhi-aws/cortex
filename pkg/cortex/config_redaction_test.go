package cortex

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// sensitiveYAMLKeySubstrings is the set of credential-shaped substrings that
// MUST only appear on YAML keys whose Go field is of type flagext.Secret.
// Keys matching any of these entries ensure that YAML/JSON marshalling of the
// live cortex.Config can never leak the field in cleartext via the
// unauthenticated /config endpoint (or anywhere else the config is dumped).
var sensitiveYAMLKeySubstrings = []string{
	"password",
	"secret",
	"credential",
	"credentials",
	"api_key",
	"access_key_id",
	"dsn",
}

// sensitiveYAMLKeySuffixes requires the key to end with the given underscore
// suffix. This avoids false positives on plural / count fields such as
// `num_tokens` or `tokens_file_path` while still catching
// `bearer_token`/`auth_token`/`acl_token`/`csrf_token`-style credential
// fields.
var sensitiveYAMLKeySuffixes = []string{
	"_token",
}

// sensitiveYAMLKeyExact is the set of credential-shaped exact YAML key names
// that MUST be of type flagext.Secret.
var sensitiveYAMLKeyExact = []string{
	"token",
	"uri",
}

// allowedPlainStringKeys lists YAML key names where a plain string is
// explicitly acceptable even though the key matches a sensitive substring.
// For example, *_file / *_path fields hold filesystem paths pointing at the
// secret, not the secret itself, and username fields hold the account name
// paired with a (separately-redacted) password.
var allowedPlainStringKeys = map[string]bool{
	"password_file":          true,
	"client_secret_file":     true,
	"basic_auth_username":    true,
	"basic_auth_password_file": true,
	"bearer_token_file":      true,
	"credentials_file":       true,
}

// keyLooksSensitive reports whether a YAML key name must be a flagext.Secret.
func keyLooksSensitive(name string) bool {
	if name == "" {
		return false
	}
	if allowedPlainStringKeys[name] {
		return false
	}
	// Fields with *_file / *_path suffixes hold a path to the secret, not the
	// secret itself. They are not required to be flagext.Secret.
	if strings.HasSuffix(name, "_file") || strings.HasSuffix(name, "_path") {
		return false
	}
	for _, exact := range sensitiveYAMLKeyExact {
		if name == exact {
			return true
		}
	}
	for _, suf := range sensitiveYAMLKeySuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	for _, sub := range sensitiveYAMLKeySubstrings {
		if strings.Contains(name, sub) {
			return true
		}
	}
	return false
}

// TestConfigCredentialFieldsAreFlagextSecret walks the live cortex.Config
// value tree and asserts that every field whose YAML key name indicates it
// holds a credential (see keyLooksSensitive) is typed as flagext.Secret. The
// Secret type's MarshalYAML returns "********", which is what prevents the
// unauthenticated /config handler from dumping cleartext credentials.
//
// If this test fails after a config field is added, convert the new field to
// flagext.Secret (or extend allowedPlainStringKeys with an explicit
// justification). Do NOT silently loosen keyLooksSensitive.
func TestConfigCredentialFieldsAreFlagextSecret(t *testing.T) {
	var cfg Config
	secretType := reflect.TypeOf(flagext.Secret{})

	var walk func(path string, t reflect.Type, seen map[reflect.Type]bool)
	walk = func(path string, typ reflect.Type, seen map[reflect.Type]bool) {
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		defer delete(seen, typ)

		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			yamlTag := f.Tag.Get("yaml")
			if yamlTag == "-" {
				continue
			}
			yamlName := strings.Split(yamlTag, ",")[0]
			nextPath := path + "." + yamlName
			if yamlName == "" {
				// inline / anonymous field; use the Go name as a path hint.
				nextPath = path + "." + f.Name
			}

			if yamlName != "" && keyLooksSensitive(yamlName) {
				require.Equalf(t, secretType, f.Type,
					"field %s (yaml:%q) must be of type flagext.Secret so YAML "+
						"marshalling redacts it. Current type: %s. If this field "+
						"genuinely does not hold a credential, extend "+
						"allowedPlainStringKeys with a justification.",
					nextPath, yamlName, f.Type.String())
			}

			ft := f.Type
			for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft != secretType {
				walk(nextPath, ft, seen)
			}
		}
	}

	walk("cortex.Config", reflect.TypeOf(cfg), map[reflect.Type]bool{})
}
