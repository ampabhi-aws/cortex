package cortex

import (
	"reflect"
	"strings"
	"testing"
)

func TestConfigNoPlaintextSecretFields(t *testing.T) {
	needles := []string{"password", "secret", "token", "key"}

	allowed := map[string]bool{
		"password_file":        true,
		"tls_key_path":         true,
		"tokens_file_path":     true,
		"client_key_file":      true,
		"server_key_file":      true,
		"key_file":             true,
		"certificate_key_file": true,
		"access_key_id":        true,
		"kms_key_id":           true,
		"sse_kms_key_id":       true,
		"s3_sse_kms_key_id":    true,
		"num_tokens":           true,
		"public_key":           true,
		"fingerprint":          true,
	}

	matches := func(name string) bool {
		lower := strings.ToLower(name)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				return true
			}
		}
		return false
	}

	strType := reflect.TypeOf("")
	visited := map[reflect.Type]bool{}

	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || visited[typ] {
			return
		}
		visited[typ] = true

		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			yamlTag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if yamlTag == "-" {
				continue
			}
			name := yamlTag
			if name == "" {
				name = f.Name
			}
			lower := strings.ToLower(name)
			if !allowed[lower] && matches(name) && f.Type == strType {
				t.Errorf("%s.%s (yaml %q) is plain string; must be flagext.Secret", path, f.Name, yamlTag)
			}
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type, path+"."+f.Name)
			}
		}
	}

	walk(reflect.TypeOf(Config{}), "Config")
}
