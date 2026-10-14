package api

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	etcdkv "github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	swiftcfg "github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// credTokens enumerates the suspicious yaml tag names that indicate secret
// material. They are joined at test time to form the matching regex, keeping
// each individual term plain to simplify review.
var credTokens = []string{
	"password",
	"api_key",
	"bearer_token",
	"access_key",
}

func credRegexp() *regexp.Regexp {
	return regexp.MustCompile("(?i)" + strings.Join(credTokens, "|"))
}

func walkCredFields(t reflect.Type, path string, seen map[reflect.Type]bool, re *regexp.Regexp) []string {
	if t == nil {
		return nil
	}
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		return walkCredFields(t.Elem(), path, seen, re)
	case reflect.Struct:
	default:
		return nil
	}
	if seen[t] {
		return nil
	}
	seen[t] = true

	secretType := reflect.TypeOf(flagext.Secret{})

	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		yamlTag := f.Tag.Get("yaml")
		if yamlTag == "-" {
			continue
		}
		name := strings.Split(yamlTag, ",")[0]
		fieldPath := path + "." + f.Name
		if re.MatchString(name) {
			if f.Type != secretType {
				out = append(out, fieldPath+" yaml="+name+" type="+f.Type.String())
			}
			continue
		}
		out = append(out, walkCredFields(f.Type, fieldPath, seen, re)...)
	}
	return out
}

func TestNoCleartextCredentialsInSwiftAndEtcdConfigs(t *testing.T) {
	re := credRegexp()
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"swift.Config", reflect.TypeOf(swiftcfg.Config{})},
		{"etcd.Config", reflect.TypeOf(etcdkv.Config{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offenders := walkCredFields(tc.typ, tc.name, map[reflect.Type]bool{}, re)
			assert.Empty(t, offenders, "offenders: %v", offenders)
		})
	}
}
