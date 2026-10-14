package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// configWithSecretsMock exercises the GET /config credential redaction. It
// embeds plain-string credential fields (modeled after swift.password,
// etcd.password, basic_auth_password, access_key_id, configs.database.uri)
// to ensure DefaultConfigHandler masks them before serving the response.
type configWithSecretsMock struct {
	TopPassword   string                 `yaml:"password"`
	TopKeyID      string                 `yaml:"access_key_id"`
	Database      configWithSecretsDBMock `yaml:"database"`
	Alertmanager  configWithSecretsAMMock `yaml:"alertmanager_client"`
	HarmlessField string                 `yaml:"harmless_field"`
}

type configWithSecretsDBMock struct {
	URI string `yaml:"uri"`
}

type configWithSecretsAMMock struct {
	BasicAuthPassword string `yaml:"basic_auth_password"`
	BasicAuthUsername string `yaml:"basic_auth_username"`
}

func TestConfigHandlerRedactsSensitiveFields(t *testing.T) {
	cfg := &configWithSecretsMock{
		TopPassword:   "super-secret",
		TopKeyID:      "AKIAEXAMPLE",
		HarmlessField: "keep-me",
	}
	cfg.Database.URI = "postgres://user:hunter2@host/db"
	cfg.Alertmanager.BasicAuthPassword = "notify-pass"
	cfg.Alertmanager.BasicAuthUsername = "notify-user"

	req := httptest.NewRequest("GET", "http://test.com/config", nil)
	w := httptest.NewRecorder()

	DefaultConfigHandler(cfg, cfg)(w, req)

	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	bodyStr := string(body)

	// Sensitive values must be redacted.
	assert.NotContains(t, bodyStr, "super-secret")
	assert.NotContains(t, bodyStr, "AKIAEXAMPLE")
	assert.NotContains(t, bodyStr, "hunter2")
	assert.NotContains(t, bodyStr, "notify-pass")
	assert.Contains(t, bodyStr, "********")

	// Non-sensitive values must survive unchanged.
	assert.Contains(t, bodyStr, "keep-me")
	assert.Contains(t, bodyStr, "notify-user")
}

func TestConfigHandlerRedactsSensitiveFieldsDefaultsMode(t *testing.T) {
	defaultCfg := &configWithSecretsMock{
		TopPassword: "baked-in-default",
	}

	req := httptest.NewRequest("GET", "http://test.com/config?mode=defaults", nil)
	w := httptest.NewRecorder()

	DefaultConfigHandler(&configWithSecretsMock{}, defaultCfg)(w, req)

	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NotContains(t, string(body), "baked-in-default")
	assert.Contains(t, string(body), "********")
}

func TestConfigHandlerRedactsSensitiveFieldsDiffMode(t *testing.T) {
	defaultCfg := &configWithSecretsMock{}
	actualCfg := &configWithSecretsMock{TopPassword: "operator-set"}

	req := httptest.NewRequest("GET", "http://test.com/config?mode=diff", nil)
	w := httptest.NewRecorder()

	DefaultConfigHandler(actualCfg, defaultCfg)(w, req)

	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NotContains(t, string(body), "operator-set")
}
