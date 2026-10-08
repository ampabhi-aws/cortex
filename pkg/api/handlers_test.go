package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func TestIndexHandlerPrefix(t *testing.T) {
	c := newIndexPageContent()
	c.AddLink(SectionAdminEndpoints, "/ingester/ring", "Ingester Ring")

	for _, tc := range []struct {
		prefix    string
		toBeFound string
	}{
		{prefix: "", toBeFound: "<a href=\"/ingester/ring\">"},
		{prefix: "/test", toBeFound: "<a href=\"/test/ingester/ring\">"},
		// All the extra slashed are cleaned up in the result.
		{prefix: "///test///", toBeFound: "<a href=\"/test/ingester/ring\">"},
	} {
		h := indexHandler(tc.prefix, c)

		req := httptest.NewRequest("GET", "/", nil)
		resp := httptest.NewRecorder()

		h.ServeHTTP(resp, req)

		require.Equal(t, 200, resp.Code)
		require.True(t, strings.Contains(resp.Body.String(), tc.toBeFound))
	}
}

func TestIndexPageContent(t *testing.T) {
	c := newIndexPageContent()
	c.AddLink(SectionAdminEndpoints, "/ingester/ring", "Ingester Ring")
	c.AddLink(SectionAdminEndpoints, "/store-gateway/ring", "Store Gateway Ring")
	c.AddLink(SectionDangerous, "/shutdown", "Shutdown")

	h := indexHandler("", c)

	req := httptest.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()

	h.ServeHTTP(resp, req)

	require.Equal(t, 200, resp.Code)
	require.True(t, strings.Contains(resp.Body.String(), SectionAdminEndpoints))
	require.True(t, strings.Contains(resp.Body.String(), SectionDangerous))
	require.True(t, strings.Contains(resp.Body.String(), "Store Gateway Ring"))
	require.True(t, strings.Contains(resp.Body.String(), "/shutdown"))
	require.False(t, strings.Contains(resp.Body.String(), "/compactor/ring"))
}

type diffConfigMock struct {
	MyInt          int          `yaml:"my_int"`
	MyFloat        float64      `yaml:"my_float"`
	MySlice        []string     `yaml:"my_slice"`
	IgnoredField   func() error `yaml:"-"`
	MyNestedStruct struct {
		MyString      string   `yaml:"my_string"`
		MyBool        bool     `yaml:"my_bool"`
		MyEmptyStruct struct{} `yaml:"my_empty_struct"`
	} `yaml:"my_nested_struct"`
}

func newDefaultDiffConfigMock() *diffConfigMock {
	c := &diffConfigMock{
		MyInt:        666,
		MyFloat:      6.66,
		MySlice:      []string{"value1", "value2"},
		IgnoredField: func() error { return nil },
	}
	c.MyNestedStruct.MyString = "string1"
	return c
}

func TestConfigDiffHandler(t *testing.T) {
	for _, tc := range []struct {
		name               string
		expectedStatusCode int
		expectedBody       string
		actualConfig       func() interface{}
	}{
		{
			name:               "no config parameters overridden",
			expectedStatusCode: 200,
			expectedBody:       "{}\n",
		},
		{
			name: "slice changed",
			actualConfig: func() interface{} {
				c := newDefaultDiffConfigMock()
				c.MySlice = append(c.MySlice, "value3")
				return c
			},
			expectedStatusCode: 200,
			expectedBody: "my_slice:\n" +
				"- value1\n" +
				"- value2\n" +
				"- value3\n",
		},
		{
			name: "string in nested struct changed",
			actualConfig: func() interface{} {
				c := newDefaultDiffConfigMock()
				c.MyNestedStruct.MyString = "string2"
				return c
			},
			expectedStatusCode: 200,
			expectedBody: "my_nested_struct:\n" +
				"  my_string: string2\n",
		},
		{
			name: "bool in nested struct changed",
			actualConfig: func() interface{} {
				c := newDefaultDiffConfigMock()
				c.MyNestedStruct.MyBool = true
				return c
			},
			expectedStatusCode: 200,
			expectedBody: "my_nested_struct:\n" +
				"  my_bool: true\n",
		},
		{
			name: "test invalid input",
			actualConfig: func() interface{} {
				c := "x"
				return &c
			},
			expectedStatusCode: 500,
			expectedBody: "yaml: unmarshal errors:\n" +
				"  line 1: cannot unmarshal !!str `x` into map[interface {}]interface {}\n",
		},
	} {
		defaultCfg := newDefaultDiffConfigMock()
		t.Run(tc.name, func(t *testing.T) {

			var actualCfg interface{}
			if tc.actualConfig != nil {
				actualCfg = tc.actualConfig()
			} else {
				actualCfg = newDefaultDiffConfigMock()
			}

			req := httptest.NewRequest("GET", "http://test.com/config?mode=diff", nil)
			w := httptest.NewRecorder()

			h := DefaultConfigHandler(actualCfg, defaultCfg)
			h(w, req)
			resp := w.Result()
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedBody, string(body))
		})
	}

}

func TestConfigOverrideHandler(t *testing.T) {
	cfg := &Config{
		CustomConfigHandler: func(_ interface{}, _ interface{}) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("config"))
				assert.NoError(t, err)
			}
		},
	}

	req := httptest.NewRequest("GET", "http://test.com/config", nil)
	w := httptest.NewRecorder()

	h := cfg.configHandler(
		struct{ name string }{name: "actual"},
		struct{ name string }{name: "default"},
	)
	h(w, req)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("config"), body)
}

// TestConfigHandler_RedactsSecrets is a regression test for the
// Unauthenticated /config endpoint credential leak: every credential-bearing
// field reachable from the handler must round-trip through yaml.Marshal as
// "********" (or an opaque URL with the password masked), never as the raw
// canary string the operator supplied.
func TestConfigHandler_RedactsSecrets(t *testing.T) {
	canaries := []string{
		"SWIFT-PASSWORD-CANARY",
		"ETCD-PASSWORD-CANARY",
		"ALERTMANAGER-BASIC-AUTH-CANARY",
		"S3-ACCESS-KEY-ID-CANARY",
		"S3-SECRET-ACCESS-KEY-CANARY",
		"CONFIGS-DB-URI-PASSWORD-CANARY",
	}

	dbURI := flagext.URLValue{}
	require.NoError(t, dbURI.Set("postgres://configs:CONFIGS-DB-URI-PASSWORD-CANARY@configs-db.weave.local/configs?sslmode=disable"))

	cfg := struct {
		Swift struct {
			Password flagext.Secret `yaml:"password"`
		} `yaml:"swift"`
		Etcd struct {
			UserName string         `yaml:"username"`
			Password flagext.Secret `yaml:"password"`
		} `yaml:"etcd"`
		BasicAuth struct {
			Username string         `yaml:"basic_auth_username"`
			Password flagext.Secret `yaml:"basic_auth_password"`
		} `yaml:"alertmanager_client"`
		S3 struct {
			AccessKeyID     flagext.Secret `yaml:"access_key_id"`
			SecretAccessKey flagext.Secret `yaml:"secret_access_key"`
		} `yaml:"s3"`
		ConfigsDB struct {
			URI flagext.URLValue `yaml:"uri"`
		} `yaml:"configs_database"`
	}{}
	cfg.Swift.Password = flagext.Secret{Value: "SWIFT-PASSWORD-CANARY"}
	cfg.Etcd.UserName = "cortex"
	cfg.Etcd.Password = flagext.Secret{Value: "ETCD-PASSWORD-CANARY"}
	cfg.BasicAuth.Username = "ruler"
	cfg.BasicAuth.Password = flagext.Secret{Value: "ALERTMANAGER-BASIC-AUTH-CANARY"}
	cfg.S3.AccessKeyID = flagext.Secret{Value: "S3-ACCESS-KEY-ID-CANARY"}
	cfg.S3.SecretAccessKey = flagext.Secret{Value: "S3-SECRET-ACCESS-KEY-CANARY"}
	cfg.ConfigsDB.URI = dbURI

	req := httptest.NewRequest("GET", "http://test.com/config", nil)
	w := httptest.NewRecorder()
	DefaultConfigHandler(&cfg, &cfg)(w, req)
	resp := w.Result()
	require.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)

	for _, canary := range canaries {
		assert.NotContainsf(t, bodyStr, canary, "canary %q leaked in /config output:\n%s", canary, bodyStr)
	}
	// Expect the standard mask to appear for secrets.
	assert.Contains(t, bodyStr, "********")
}

// TestConfigHandler_DisabledByDefault verifies that when ExposeConfig is left
// at its (false) default, the /config endpoint returns 404 instead of serving
// the configuration dump.
func TestConfigHandler_DisabledByDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/config", nil)
	w := httptest.NewRecorder()
	http.HandlerFunc(disabledConfigHandler).ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
