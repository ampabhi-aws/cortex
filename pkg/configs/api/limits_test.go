package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/configs/db/dbtest"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// fakeLimits implements Limits for tests.
type fakeLimits struct {
	maxConfigSize       int
	maxTemplatesCount   int
	maxTemplateSize     int
	maxRuleGroups       int
	maxRulesPerGroup    int
}

func (f *fakeLimits) AlertmanagerMaxConfigSize(string) int     { return f.maxConfigSize }
func (f *fakeLimits) AlertmanagerMaxTemplatesCount(string) int { return f.maxTemplatesCount }
func (f *fakeLimits) AlertmanagerMaxTemplateSize(string) int   { return f.maxTemplateSize }
func (f *fakeLimits) RulerMaxRuleGroupsPerTenant(string) int   { return f.maxRuleGroups }
func (f *fakeLimits) RulerMaxRulesPerRuleGroup(string) int     { return f.maxRulesPerGroup }

func setupWithLimits(t *testing.T, l Limits) (*API, db.DB) {
	database := dbtest.Setup(t)
	a := NewWithLimits(database, Config{Notifications: NotificationsConfig{DisableEmail: true}}, l)
	return a, database
}

func doRequest(t *testing.T, h http.Handler, userID, method, path, contentType string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, path, body)
	require.NoError(t, err)
	r = r.WithContext(user.InjectOrgID(r.Context(), userID))
	require.NoError(t, user.InjectOrgIDIntoHTTPRequest(r.Context(), r))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	h.ServeHTTP(w, r)
	return w
}

// Oversized bodies are rejected before decoding so a tenant cannot exhaust
// memory on shared replicas.
func Test_SetConfig_RejectsOversizedBody(t *testing.T) {
	a, database := setupWithLimits(t, &fakeLimits{maxConfigSize: 128})
	defer dbtest.Cleanup(t, database)

	cfg := userconfig.Config{
		AlertmanagerConfig: strings.Repeat("x", 4096),
		RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	resp := doRequest(t, a, "tenant-a", "POST", "/api/prom/configs/alertmanager", "", bytes.NewReader(b))
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code, "body: %s", resp.Body.String())
}

// With no limits configured (default), legacy unbounded behavior is preserved.
func Test_SetConfig_NoLimits_AcceptsLargeBody(t *testing.T) {
	a, database := setupWithLimits(t, &fakeLimits{})
	defer dbtest.Cleanup(t, database)

	cfg := userconfig.Config{
		AlertmanagerConfig: "route:\n  receiver: noop\nreceivers:\n- name: noop",
		RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	resp := doRequest(t, a, "tenant-a", "POST", "/api/prom/configs/alertmanager", "", bytes.NewReader(b))
	assert.Equal(t, http.StatusNoContent, resp.Code, "body: %s", resp.Body.String())
}

// Too many template files are rejected regardless of per-file size.
func Test_SetConfig_RejectsTooManyTemplates(t *testing.T) {
	a, database := setupWithLimits(t, &fakeLimits{maxTemplatesCount: 2})
	defer dbtest.Cleanup(t, database)

	templates := map[string]string{}
	for i := 0; i < 10; i++ {
		templates[fmt.Sprintf("t%d.tmpl", i)] = "ok"
	}
	cfg := userconfig.Config{
		AlertmanagerConfig: "route:\n  receiver: noop\nreceivers:\n- name: noop",
		TemplateFiles:      templates,
		RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	resp := doRequest(t, a, "tenant-a", "POST", "/api/prom/configs/alertmanager", "", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "too many templates")
}

// Oversized templates are rejected.
func Test_SetConfig_RejectsOversizedTemplate(t *testing.T) {
	a, database := setupWithLimits(t, &fakeLimits{maxTemplateSize: 16})
	defer dbtest.Cleanup(t, database)

	cfg := userconfig.Config{
		AlertmanagerConfig: "route:\n  receiver: noop\nreceivers:\n- name: noop",
		TemplateFiles:      map[string]string{"big.tmpl": strings.Repeat("y", 1024)},
		RulesConfig:        userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	resp := doRequest(t, a, "tenant-a", "POST", "/api/prom/configs/alertmanager", "", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "too big")
}

// Too many rule files are rejected.
func Test_SetConfig_RejectsTooManyRuleGroups(t *testing.T) {
	a, database := setupWithLimits(t, &fakeLimits{maxRuleGroups: 1})
	defer dbtest.Cleanup(t, database)

	ruleBody := "groups:\n- name: g1\n  rules:\n  - record: foo\n    expr: 1\n"
	cfg := userconfig.Config{
		RulesConfig: userconfig.RulesConfig{
			FormatVersion: userconfig.RuleFormatV2,
			Files: map[string]string{
				"r1.yml": ruleBody,
				"r2.yml": ruleBody,
			},
		},
	}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	resp := doRequest(t, a, "tenant-a", "POST", "/api/prom/configs/rules", "", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "too many rule groups")
}
