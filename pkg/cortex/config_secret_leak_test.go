package cortex

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestConfigNoPlaintextSecretFields walks the full cortex Config reflectively
// and fails on any plain string field whose Go name or yaml tag matches
// password, secret, token or credential. Such a field would be emitted
// verbatim by the unauthenticated /config YAML dump: credentials must be
// declared as flagext.Secret (or similar redacting type) so that MarshalYAML
// redacts them before serialization.
//
// Fields that happen to contain one of the trigger substrings but are not
// credentials themselves (file paths, URLs, header names) are filtered by
// their yaml tag or Go name suffix.
func TestConfigNoPlaintextSecretFields(t *testing.T) {
	cfg := newDefaultConfig()

	trigger := regexp.MustCompile("(?i)(password|secret|token|credential)")

	safeTagSuffixes := []string{"_file", "_path", "_url", "_header"}
	safeNameParts := []string{"File", "Path", "URL", "Url", "Header"}

	isSafe := func(name, yamlTag string) bool {
		lt := strings.ToLower(yamlTag)
		for _, s := range safeTagSuffixes {
			if strings.HasSuffix(lt, s) {
				return true
			}
		}
		for _, s := range safeNameParts {
			if strings.Contains(name, s) {
				return true
			}
		}
		return false
	}

	seen := map[reflect.Type]bool{}
	var walk func(path string, v reflect.Value)
	walk = func(path string, v reflect.Value) {
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				return
			}
			walk(path, v.Elem())
			return
		case reflect.Interface:
			if v.IsNil() {
				return
			}
			walk(path, v.Elem())
			return
		case reflect.Struct:
			rt := v.Type()
			if seen[rt] {
				return
			}
			seen[rt] = true
			for i := 0; i < rt.NumField(); i++ {
				sf := rt.Field(i)
				if !sf.IsExported() {
					continue
				}
				yamlTag := strings.Split(sf.Tag.Get("yaml"), ",")[0]
				if yamlTag == "-" {
					continue
				}
				child := v.Field(i)
				fieldPath := sf.Name
				if path != "" {
					fieldPath = path + "." + sf.Name
				}
				if child.Kind() == reflect.String {
					name := sf.Name
					if trigger.MatchString(name) || trigger.MatchString(yamlTag) {
						if isSafe(name, yamlTag) {
							continue
						}
						t.Errorf("field %s (yaml:%q) is a plain string that looks like a credential; declare it as flagext.Secret so it is redacted in /config dumps", fieldPath, yamlTag)
					}
					continue
				}
				walk(fieldPath, child)
			}
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Struct {
				walk(path+"[]", reflect.New(v.Type().Elem()).Elem())
			}
		}
	}

	walk("", reflect.ValueOf(cfg).Elem())
}
