package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cortexproject/cortex/pkg/configs/db/dbtest"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rulesEndpoint        = "/api/prom/configs/rules"
	rulesPrivateEndpoint = "/private/api/prom/configs/rules"

	alertManagerConfigEndpoint        = "/api/prom/configs/alertmanager"
	alertManagerConfigPrivateEndpoint = "/private/api/prom/configs/alertmanager"
)

var (
	rulesClient              = configurable{rulesEndpoint, rulesPrivateEndpoint}
	alertManagerConfigClient = configurable{alertManagerConfigEndpoint, alertManagerConfigPrivateEndpoint}

	allClients = []configurable{rulesClient, alertManagerConfigClient}
)

// The root page returns 200 OK.
func Test_Root_OK(t *testing.T) {
	setup(t)
	defer cleanup(t)

	w := request(t, "GET", "/", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

type configurable struct {
	Endpoint        string
	PrivateEndpoint string
}

// post a config
func (c configurable) post(t *testing.T, userID string, config userconfig.Config) userconfig.View {
	w := requestAsUser(t, userID, "POST", c.Endpoint, "", readerFromConfig(t, config))
	require.Equal(t, http.StatusNoContent, w.Code)
	return c.get(t, userID)
}

// get a config
func (c configurable) get(t *testing.T, userID string) userconfig.View {
	w := requestAsUser(t, userID, "GET", c.Endpoint, "", nil)
	return parseView(t, w.Body.Bytes())
}

// configs returns 401 to requests without authentication.
func Test_GetConfig_Anonymous(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, c := range allClients {
		w := request(t, "GET", c.Endpoint, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}
}

// configs returns 404 if no config has been created yet.
func Test_GetConfig_NotFound(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	for _, c := range allClients {
		w := requestAsUser(t, userID, "GET", c.Endpoint, "", nil)
		assert.Equal(t, http.StatusNotFound, w.Code)
	}
}

// configs returns 401 to requests without authentication.
func Test_PostConfig_Anonymous(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, c := range allClients {
		w := request(t, "POST", c.Endpoint, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}
}

// Posting to a configuration sets it so that you can get it again.
func Test_PostConfig_CreatesConfig(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	config := makeConfig()
	for _, c := range allClients {
		{
			w := requestAsUser(t, userID, "POST", c.Endpoint, "", readerFromConfig(t, config))
			assert.Equal(t, http.StatusNoContent, w.Code)
		}
		{
			w := requestAsUser(t, userID, "GET", c.Endpoint, "", nil)
			assert.Equal(t, config, parseView(t, w.Body.Bytes()).Config)
		}
	}
}

// Posting to a configuration sets it so that you can get it again.
func Test_PostConfig_UpdatesConfig(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	for _, c := range allClients {
		view1 := c.post(t, userID, makeConfig())
		config2 := makeConfig()
		view2 := c.post(t, userID, config2)
		assert.True(t, view2.ID > view1.ID, "%v > %v", view2.ID, view1.ID)
		assert.Equal(t, config2, view2.Config)
	}
}

// Different users can have different configurations.
func Test_PostConfig_MultipleUsers(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID1 := makeUserID()
	userID2 := makeUserID()
	for _, c := range allClients {
		config1 := c.post(t, userID1, makeConfig())
		config2 := c.post(t, userID2, makeConfig())
		foundConfig1 := c.get(t, userID1)
		assert.Equal(t, config1, foundConfig1)
		foundConfig2 := c.get(t, userID2)
		assert.Equal(t, config2, foundConfig2)
		assert.True(t, config2.ID > config1.ID, "%v > %v", config2.ID, config1.ID)
	}
}

// GetAllConfigs returns an empty list of configs if there aren't any.
func Test_GetAllConfigs_Empty(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, c := range allClients {
		w := request(t, "GET", c.PrivateEndpoint, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var found ConfigsView
		err := json.Unmarshal(w.Body.Bytes(), &found)
		assert.NoError(t, err, "Could not unmarshal JSON")
		assert.Equal(t, ConfigsView{Configs: map[string]userconfig.View{}}, found)
	}
}

// GetAllConfigs returns all created userconfig.
func Test_GetAllConfigs(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	config := makeConfig()

	for _, c := range allClients {
		view := c.post(t, userID, config)
		w := request(t, "GET", c.PrivateEndpoint, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var found ConfigsView
		err := json.Unmarshal(w.Body.Bytes(), &found)
		assert.NoError(t, err, "Could not unmarshal JSON")
		assert.Equal(t, ConfigsView{Configs: map[string]userconfig.View{
			userID: view,
		}}, found)
	}
}

// GetAllConfigs returns the *newest* versions of all created userconfig.
func Test_GetAllConfigs_Newest(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()

	for _, c := range allClients {
		c.post(t, userID, makeConfig())
		c.post(t, userID, makeConfig())
		lastCreated := c.post(t, userID, makeConfig())

		w := request(t, "GET", c.PrivateEndpoint, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var found ConfigsView
		err := json.Unmarshal(w.Body.Bytes(), &found)
		assert.NoError(t, err, "Could not unmarshal JSON")
		assert.Equal(t, ConfigsView{Configs: map[string]userconfig.View{
			userID: lastCreated,
		}}, found)
	}
}

func Test_GetConfigs_IncludesNewerConfigsAndExcludesOlder(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, c := range allClients {
		c.post(t, makeUserID(), makeConfig())
		config2 := c.post(t, makeUserID(), makeConfig())
		userID3 := makeUserID()
		config3 := c.post(t, userID3, makeConfig())

		w := request(t, "GET", fmt.Sprintf("%s?since=%d", c.PrivateEndpoint, config2.ID), nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var found ConfigsView
		err := json.Unmarshal(w.Body.Bytes(), &found)
		assert.NoError(t, err, "Could not unmarshal JSON")
		assert.Equal(t, ConfigsView{Configs: map[string]userconfig.View{
			userID3: config3,
		}}, found)
	}
}

var amCfgValidationTests = []struct {
	config      string
	shouldFail  bool
	errContains string
}{
	{
		config:      "invalid config",
		shouldFail:  true,
		errContains: "yaml",
	}, {
		config: `
        global:
          smtp_smarthost: localhost:25
          smtp_from: alertmanager@example.org
        route:
          receiver: noop

        receivers:
        - name: noop
          email_configs:
          - to: myteam@foobar.org`,
		shouldFail:  true,
		errContains: ErrEmailNotificationsAreDisabled.Error(),
	}, {
		config: `
        global:
          smtp_smarthost: localhost:25
          smtp_from: alertmanager@example.org
        route:
          receiver: noop

        receivers:
        - name: noop
          slack_configs:
          - api_url: http://slack`,
		shouldFail: false,
	},
}

func Test_ValidateAlertmanagerConfig(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	for i, test := range amCfgValidationTests {
		resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager/validate", "", strings.NewReader(test.config))
		data := map[string]string{}
		err := json.Unmarshal(resp.Body.Bytes(), &data)
		assert.NoError(t, err, "test case %d", i)

		success := map[string]string{
			"status": "success",
		}
		if !test.shouldFail {
			assert.Equal(t, success, data, "test case %d", i)
			assert.Equal(t, http.StatusOK, resp.Code, "test case %d", i)
			continue
		}

		assert.Equal(t, "error", data["status"], "test case %d", i)
		assert.Contains(t, data["error"], test.errContains, "test case %d", i)
	}
}

func Test_SetConfig_ValidatesAlertmanagerConfig(t *testing.T) {
	setup(t)
	defer cleanup(t)

	userID := makeUserID()
	for i, test := range amCfgValidationTests {
		cfg := userconfig.Config{AlertmanagerConfig: test.config, RulesConfig: userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2}}
		resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager", "", readerFromConfig(t, cfg))

		if !test.shouldFail {
			assert.Equal(t, http.StatusNoContent, resp.Code, "test case %d", i)
			continue
		}

		assert.Equal(t, http.StatusBadRequest, resp.Code, "test case %d", i)
		assert.Contains(t, resp.Body.String(), test.errContains, "test case %d", i)
	}
}

func Test_SetConfig_ValidatesAlertmanagerConfig_WithEmailEnabled(t *testing.T) {
	config := `
        global:
          smtp_smarthost: localhost:25
          smtp_from: alertmanager@example.org
        route:
          receiver: noop

        receivers:
        - name: noop
          email_configs:
          - to: myteam@foobar.org`
	setupWithEmailEnabled(t)
	defer cleanup(t)

	userID := makeUserID()
	cfg := userconfig.Config{AlertmanagerConfig: config, RulesConfig: userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2}}
	resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager", "", readerFromConfig(t, cfg))

	assert.Equal(t, http.StatusNoContent, resp.Code)
}

func Test_SetConfig_BodyFormat(t *testing.T) {
	setup(t)
	defer cleanup(t)
	for _, bodyFile := range []string{"testdata/config.yml", "testdata/config.json"} {
		var contentType string
		switch path.Ext(bodyFile) {
		case ".yml":
			contentType = "text/yaml"
		default:
			contentType = "text/json"
		}
		testSetConfigBodyFormat(bodyFile, contentType, t)
	}
}

func testSetConfigBodyFormat(bodyFile string, contentType string, t *testing.T) {
	userID := makeUserID()
	file, err := os.Open(bodyFile)
	require.NoError(t, err)
	defer file.Close()
	resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager", contentType, file)
	assert.Equal(t, http.StatusNoContent, resp.Code, "error body: %s Content-Type: %s", resp.Body.String(), contentType)
}

func TestParseConfigFormat(t *testing.T) {
	tests := []struct {
		name          string
		defaultFormat string
		expected      string
	}{
		{"", FormatInvalid, FormatInvalid},
		{"", FormatJSON, FormatJSON},
		{"application/json", FormatInvalid, FormatJSON},
		{"application/yaml", FormatInvalid, FormatYAML},
		{"application/json, application/yaml", FormatInvalid, FormatJSON},
		{"application/yaml, application/json", FormatInvalid, FormatYAML},
		{"text/plain, application/yaml", FormatInvalid, FormatYAML},
		{"application/yaml; a=1", FormatInvalid, FormatYAML},
	}
	for _, test := range tests {
		t.Run(test.name+"_"+test.expected, func(t *testing.T) {
			actual := parseConfigFormat(test.name, test.defaultFormat)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func Test_SetConfig_ValidateTemplateFiles(t *testing.T) {
	cfg := userconfig.Config{
		TemplateFiles: map[string]string{
			"mytemplate.tmpl": `
				{{ define "mytemplate" }}
				ToUpper{{ .Value | toUpper }}
				ToLower{{ .Value | toLower }}
				Title{{ .Value | title }}
				Join{{ .Values | join " " }}
				Match{{ .Value | match "fir" }}
				SafeHTML{{ .Value | safeHtml }}
				ReReplaceAll{{ .Value | reReplaceAll "-" "_" }}
				StringSlice{{ .Value | stringSlice }}
				{{ end }}
			`,
		},
	}

	err := validateTemplateFiles(cfg)
	assert.Equal(t, nil, err)
}

// Test_PrivateEndpoint_RejectsUnauthenticated proves that the aggregate
// /private/api/prom/configs/* endpoints no longer serve cluster-wide
// configuration to anonymous callers (CWE-1220).
func Test_PrivateEndpoint_RejectsUnauthenticated(t *testing.T) {
	setup(t)
	defer cleanup(t)

	// Seed a config so an unauthenticated caller would otherwise see it.
	_ = rulesClient.post(t, makeUserID(), makeConfig())

	for _, endpoint := range []string{
		"/private/api/prom/configs/rules",
		"/private/api/prom/configs/alertmanager",
	} {
		// No Authorization header at all.
		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)
		app.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, "endpoint=%s", endpoint)

		// Wrong token.
		w = httptest.NewRecorder()
		r, err = http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)
		r.Header.Set("Authorization", "Bearer not-the-right-token")
		app.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, "endpoint=%s wrong-token", endpoint)
	}
}

// Test_PrivateEndpoint_DisabledWhenTokenEmpty proves the handler fails
// closed when no shared token has been configured, so a misconfiguration
// cannot leak cross-tenant data by accident.
func Test_PrivateEndpoint_DisabledWhenTokenEmpty(t *testing.T) {
	database = dbtest.Setup(t)
	defer dbtest.Cleanup(t, database)
	app = New(database, Config{
		Notifications: NotificationsConfig{DisableEmail: true},
		// PrivateAPIToken intentionally left empty.
	})
	counter = 0

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/private/api/prom/configs/rules", nil)
	require.NoError(t, err)
	// Even with a valid-looking bearer header, the endpoint must stay closed.
	r.Header.Set("Authorization", "Bearer anything")
	app.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// Test_PrivateEndpoint_RedactsAlertmanagerSecrets proves that the raw
// Alertmanager YAML returned by the aggregate endpoint has secret-bearing
// values stripped, so a compromised consumer never sees Slack webhooks,
// PagerDuty keys, SMTP/basic-auth passwords, bearer tokens, etc.
func Test_PrivateEndpoint_RedactsAlertmanagerSecrets(t *testing.T) {
	setup(t)
	defer cleanup(t)

	const amCfg = `route:
  receiver: s
receivers:
- name: s
  slack_configs:
  - api_url: https://hooks.slack.com/services/T000/B000/TENANT-SECRET
    channel: "#a"
`
	userID := makeUserID()
	cfg := userconfig.Config{
		AlertmanagerConfig: amCfg,
		RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
	// Post via raw request to bypass the Alertmanager config validator.
	w := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager", "", readerFromConfig(t, cfg))
	require.Equal(t, http.StatusNoContent, w.Code, "body: %s", w.Body.String())

	w = request(t, "GET", "/private/api/prom/configs/alertmanager", nil)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "TENANT-SECRET")
	assert.Contains(t, body, redactionMarker)
}

func Test_RedactAlertmanagerSecrets(t *testing.T) {
	in := `route:
  receiver: s
receivers:
- name: s
  slack_configs:
  - api_url: https://hooks.slack.com/leak
  email_configs:
  - auth_password: SMTP-SECRET
  http_config:
    bearer_token: BEARER-SECRET
    authorization:
      credentials: CREDS-SECRET
`
	out := redactAlertmanagerSecrets(in)
	for _, s := range []string{"https://hooks.slack.com/leak", "SMTP-SECRET", "BEARER-SECRET", "CREDS-SECRET"} {
		assert.NotContains(t, out, s, "secret %q leaked", s)
	}
}
