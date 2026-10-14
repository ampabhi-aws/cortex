package cortex

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// credentialTagSubstrings are case-insensitive YAML tag fragments that indicate
// a field is expected to hold a credential and therefore must be marshalled
// through flagext.Secret so that endpoints such as GET /config redact it.
var credentialTagSubstrings = []string{
	"password",
	"secret",
	"api_key",
	"apikey",
	"access_key",
	"account_key",
	"acl_token",
	"auth_token",
	"service_account",
}

// TestCortexConfig_NoPlainStringCredentialFields asserts that no field in the
// cortex.Config tree is a plain string with a credential-like yaml tag. Any
// such field would be serialised verbatim by DefaultConfigHandler (served at
// GET /config) because only fields typed flagext.Secret are redacted. New
// credential fields must therefore be declared as flagext.Secret.
func TestCortexConfig_NoPlainStringCredentialFields(t *testing.T) {
	var cfg Config
	seen := map[reflect.Type]bool{}
	offenders := []string{}
	walkConfigStruct(reflect.TypeOf(cfg), "cortex.Config", seen, &offenders)
	assert.Empty(t, offenders,
		"found plain-string credential fields reachable from cortex.Config; "+
			"convert each to flagext.Secret so GET /config redacts it: %v", offenders)
}

func walkConfigStruct(t reflect.Type, path string, seen map[reflect.Type]bool, offenders *[]string) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	if seen[t] {
		return
	}
	seen[t] = true

	secretType := reflect.TypeOf(flagext.Secret{})

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := strings.ToLower(strings.Split(f.Tag.Get("yaml"), ",")[0])
		fieldPath := path + "." + f.Name

		if f.Type.Kind() == reflect.String && f.Type != secretType && hasCredentialTag(tag) {
			*offenders = append(*offenders, fieldPath+" yaml="+tag)
		}

		ft := f.Type
		switch ft.Kind() {
		case reflect.Ptr:
			walkConfigStruct(ft.Elem(), fieldPath, seen, offenders)
		case reflect.Struct:
			if ft == secretType {
				continue
			}
			walkConfigStruct(ft, fieldPath, seen, offenders)
		case reflect.Slice, reflect.Array:
			elem := ft.Elem()
			if elem.Kind() == reflect.Struct || elem.Kind() == reflect.Ptr {
				walkConfigStruct(elem, fieldPath+"[]", seen, offenders)
			}
		case reflect.Map:
			elem := ft.Elem()
			if elem.Kind() == reflect.Struct || elem.Kind() == reflect.Ptr {
				walkConfigStruct(elem, fieldPath+"[*]", seen, offenders)
			}
		}
	}
}

func hasCredentialTag(tag string) bool {
	if tag == "" {
		return false
	}
	// Path-to-credential fields (e.g. password_file, token_file) hold file
	// paths rather than the credential itself and are intentionally kept as
	// plain strings; path disclosure is a separate concern.
	if strings.HasSuffix(tag, "_file") {
		return false
	}
	// access_key_id (e.g. AWS access key ID) is an identifier, not a secret.
	// Only the matching secret_access_key must be a flagext.Secret, which is
	// still enforced by the "secret" / "access_key" matchers below applied to
	// other tag names.
	if tag == "access_key_id" {
		return false
	}
	for _, s := range credentialTagSubstrings {
		if strings.Contains(tag, s) {
			return true
		}
	}
	return false
}
