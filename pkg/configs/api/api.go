package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/go-kit/log/level"
	"github.com/gorilla/mux"
	amconfig "github.com/prometheus/alertmanager/config"
	amtemplate "github.com/prometheus/alertmanager/template"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

var (
	ErrEmailNotificationsAreDisabled   = errors.New("email notifications are disabled")
	ErrWebhookNotificationsAreDisabled = errors.New("webhook notifications are disabled")
)

// Config configures Configs API
type Config struct {
	Notifications NotificationsConfig `yaml:"notifications"`

	// PrivateAPIToken, when non-empty, is required as a bearer credential in
	// the Authorization header to call the cross-tenant /private/api/prom/configs/*
	// endpoints. When empty, the aggregate endpoints are disabled entirely
	// (they return HTTP 403) to prevent unauthenticated cross-tenant disclosure.
	PrivateAPIToken string `yaml:"private_api_token"`
}

// NotificationsConfig configures Alertmanager notifications method.
type NotificationsConfig struct {
	DisableEmail   bool `yaml:"disable_email"`
	DisableWebHook bool `yaml:"disable_webhook"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Notifications.DisableEmail, "configs.notifications.disable-email", false, "Disable Email notifications for Alertmanager.")
	f.BoolVar(&cfg.Notifications.DisableWebHook, "configs.notifications.disable-webhook", false, "Disable WebHook notifications for Alertmanager.")
	f.StringVar(&cfg.PrivateAPIToken, "configs.private-api-token", "", "Shared bearer credential required to access the cross-tenant /private/api/prom/configs/{rules,alertmanager} endpoints. When empty, those aggregate endpoints are disabled.")
}

// API implements the configs api.
type API struct {
	http.Handler
	db  db.DB
	cfg Config
}

// New creates a new API
func New(database db.DB, cfg Config) *API {
	a := &API{
		db:  database,
		cfg: cfg,
	}
	r := mux.NewRouter()
	a.RegisterRoutes(r)
	a.Handler = r
	return a
}

func (a *API) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!doctype html>
<html>
	<head><title>configs :: configuration service</title></head>
	<body>
		<h1>configs :: configuration service</h1>
	</body>
</html>
`)
}

// Route describes a single HTTP route registered by the configs API.
type Route struct {
	Name, Method, Path string
	Handler            http.HandlerFunc
}

// UserRoutes returns the tenant-facing routes. These are expected to be
// registered behind the standard pkg/api auth middleware (which requires an
// X-Scope-OrgID header), so individual handlers can rely on
// tenant.ExtractTenantIDFromHTTPRequest to identify the caller.
func (a *API) UserRoutes() []Route {
	return []Route{
		{"root", "GET", "/", a.admin},
		// Dedicated APIs for updating rules config. In the future, these *must*
		// be used.
		{"get_rules", "GET", "/api/prom/configs/rules", a.getConfig},
		{"set_rules", "POST", "/api/prom/configs/rules", a.setConfig},
		{"get_templates", "GET", "/api/prom/configs/templates", a.getConfig},
		{"set_templates", "POST", "/api/prom/configs/templates", a.setConfig},
		{"get_alertmanager_config", "GET", "/api/prom/configs/alertmanager", a.getConfig},
		{"set_alertmanager_config", "POST", "/api/prom/configs/alertmanager", a.setConfig},
		{"validate_alertmanager_config", "POST", "/api/prom/configs/alertmanager/validate", a.validateAlertmanagerConfig},
		{"deactivate_config", "DELETE", "/api/prom/configs/deactivate", a.deactivateConfig},
		{"restore_config", "POST", "/api/prom/configs/restore", a.restoreConfig},
	}
}

// PrivateRoutes returns the cross-tenant aggregate routes. These are gated
// at request time by a shared bearer token (see Config.PrivateAPIToken); the
// handler also redacts secret-bearing fields before serializing responses.
func (a *API) PrivateRoutes() []Route {
	return []Route{
		// Internal APIs.
		{"private_get_rules", "GET", "/private/api/prom/configs/rules", a.getConfigs},
		{"private_get_alertmanager_config", "GET", "/private/api/prom/configs/alertmanager", a.getConfigs},
	}
}

// RegisterRoutes registers the configs API HTTP routes with the provided Router.
//
// Deprecated: prefer registering through pkg/api so the shared auth middleware
// is applied to the tenant-facing routes. This method is retained for the
// in-package tests, which exercise the handler stack directly.
func (a *API) RegisterRoutes(r *mux.Router) {
	for _, route := range a.UserRoutes() {
		r.Handle(route.Path, route.Handler).Methods(route.Method).Name(route.Name)
	}
	for _, route := range a.PrivateRoutes() {
		r.Handle(route.Path, route.Handler).Methods(route.Method).Name(route.Name)
	}
}

// getConfig returns the request configuration.
func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	userID, _, err := tenant.ExtractTenantIDFromHTTPRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	logger := util_log.WithContext(r.Context(), util_log.Logger)

	cfg, err := a.db.GetConfig(r.Context(), userID)
	if err == sql.ErrNoRows {
		http.Error(w, "No configuration", http.StatusNotFound)
		return
	} else if err != nil {
		// XXX: Untested
		level.Error(logger).Log("msg", "error getting config", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch parseConfigFormat(r.Header.Get("Accept"), FormatJSON) {
	case FormatJSON:
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(cfg)
	case FormatYAML:
		w.Header().Set("Content-Type", "application/yaml")
		err = yaml.NewEncoder(w).Encode(cfg)
	default:
		// should never reach this point
		level.Error(logger).Log("msg", "unexpected error detecting the config format")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err != nil {
		// XXX: Untested
		level.Error(logger).Log("msg", "error encoding config", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *API) setConfig(w http.ResponseWriter, r *http.Request) {
	userID, _, err := tenant.ExtractTenantIDFromHTTPRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	logger := util_log.WithContext(r.Context(), util_log.Logger)

	var cfg userconfig.Config
	switch parseConfigFormat(r.Header.Get("Content-Type"), FormatJSON) {
	case FormatJSON:
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			// XXX: Untested
			level.Error(logger).Log("msg", "error decoding json body", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case FormatYAML:
		if err := yaml.NewDecoder(r.Body).Decode(&cfg); err != nil {
			// XXX: Untested
			level.Error(logger).Log("msg", "error decoding yaml body", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		// should never reach this point
		level.Error(logger).Log("msg", "unexpected error detecting the config format")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := validateAlertmanagerConfig(cfg.AlertmanagerConfig, a.cfg.Notifications); err != nil && cfg.AlertmanagerConfig != "" {
		level.Error(logger).Log("msg", "invalid Alertmanager config", "err", err)
		http.Error(w, fmt.Sprintf("Invalid Alertmanager config: %v", err), http.StatusBadRequest)
		return
	}
	if err := validateRulesFiles(cfg); err != nil {
		level.Error(logger).Log("msg", "invalid rules", "err", err)
		http.Error(w, fmt.Sprintf("Invalid rules: %v", err), http.StatusBadRequest)
		return
	}
	if err := validateTemplateFiles(cfg); err != nil {
		level.Error(logger).Log("msg", "invalid templates", "err", err)
		http.Error(w, fmt.Sprintf("Invalid templates: %v", err), http.StatusBadRequest)
		return
	}
	if err := a.db.SetConfig(r.Context(), userID, cfg); err != nil {
		// XXX: Untested
		level.Error(logger).Log("msg", "error storing config", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) validateAlertmanagerConfig(w http.ResponseWriter, r *http.Request) {
	logger := util_log.WithContext(r.Context(), util_log.Logger)
	cfg, err := io.ReadAll(r.Body)
	if err != nil {
		level.Error(logger).Log("msg", "error reading request body", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = validateAlertmanagerConfig(string(cfg), a.cfg.Notifications); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		util.WriteJSONResponse(w, map[string]string{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	util.WriteJSONResponse(w, map[string]string{
		"status": "success",
	})
}

func validateAlertmanagerConfig(cfg string, noCfg NotificationsConfig) error {
	amCfg, err := amconfig.Load(cfg)
	if err != nil {
		return err
	}

	for _, recv := range amCfg.Receivers {
		if noCfg.DisableEmail && len(recv.EmailConfigs) > 0 {
			return ErrEmailNotificationsAreDisabled
		}
		if noCfg.DisableWebHook && len(recv.WebhookConfigs) > 0 {
			return ErrWebhookNotificationsAreDisabled
		}
	}

	return nil
}

func validateRulesFiles(c userconfig.Config) error {
	_, err := c.RulesConfig.Parse()
	return err
}

func validateTemplateFiles(c userconfig.Config) error {
	for fn, content := range c.TemplateFiles {
		if _, err := template.New(fn).Funcs(template.FuncMap(amtemplate.DefaultFuncs)).Parse(content); err != nil {
			return err
		}
	}

	return nil
}

// ConfigsView renders multiple configurations, mapping userID to userconfig.View.
// Exposed only for tests.
type ConfigsView struct {
	Configs map[string]userconfig.View `json:"configs"`
}

// authorizePrivate enforces the shared bearer-token credential required for
// the cross-tenant aggregate endpoints. It uses a constant-time comparison
// and fails closed when no token is configured so the endpoint cannot leak
// every tenant's configuration without an explicit operator opt-in.
func (a *API) authorizePrivate(w http.ResponseWriter, r *http.Request) bool {
	if a.cfg.PrivateAPIToken == "" {
		http.Error(w, "forbidden: cross-tenant configs endpoint disabled (set -configs.private-api-token to enable)", http.StatusForbidden)
		return false
	}
	expected := []byte("Bearer " + a.cfg.PrivateAPIToken)
	got := []byte(r.Header.Get("Authorization"))
	if len(expected) != len(got) || subtle.ConstantTimeCompare(expected, got) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (a *API) getConfigs(w http.ResponseWriter, r *http.Request) {
	if !a.authorizePrivate(w, r) {
		return
	}
	var cfgs map[string]userconfig.View
	var cfgErr error
	logger := util_log.WithContext(r.Context(), util_log.Logger)
	rawSince := r.FormValue("since")
	if rawSince == "" {
		cfgs, cfgErr = a.db.GetAllConfigs(r.Context())
	} else {
		since, err := strconv.ParseUint(rawSince, 10, 0)
		if err != nil {
			level.Info(logger).Log("msg", "invalid config ID", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfgs, cfgErr = a.db.GetConfigs(r.Context(), userconfig.ID(since))
	}

	if cfgErr != nil {
		// XXX: Untested
		level.Error(logger).Log("msg", "error getting configs", "err", cfgErr)
		http.Error(w, cfgErr.Error(), http.StatusInternalServerError)
		return
	}

	// Redact secret-bearing fields from the raw Alertmanager YAML before
	// serializing: aggregate responses are consumed by the ruler/alertmanager
	// over an authenticated channel, but they only need rule and routing
	// structure — not Slack/PagerDuty webhooks, SMTP passwords, bearer
	// tokens, etc. Redacting here contains blast radius even if the shared
	// token leaks.
	redacted := make(map[string]userconfig.View, len(cfgs))
	for id, v := range cfgs {
		v.Config.AlertmanagerConfig = redactAlertmanagerSecrets(v.Config.AlertmanagerConfig)
		redacted[id] = v
	}

	view := ConfigsView{Configs: redacted}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(view); err != nil {
		// XXX: Untested
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// redactionMarker is substituted for the value of any secret-bearing YAML
// key in alertmanager configuration returned by the cross-tenant endpoint.
const redactionMarker = "<redacted>"

// secretKeyRE matches YAML keys whose values commonly hold third-party
// credentials in Alertmanager configuration: webhook URLs (slack_configs,
// webhook_configs, oauth2.*), API/service/routing keys (PagerDuty,
// VictorOps, OpsGenie, Pushover, WeChat, Telegram), SMTP/basic-auth
// passwords, and bearer tokens.
var secretKeyRE = regexp.MustCompile(`(?mi)^(\s*)([A-Za-z0-9_-]*(?:api_url|url_file|service_key|routing_key|api_key|auth_token|bearer_token|bot_token|user_key|password|password_file|secret|secret_file|_key|_key_file|credentials|_token)\s*:\s*)(\S.*|"[^"]*"|'[^']*')\s*$`)

// redactAlertmanagerSecrets takes a raw Alertmanager YAML document and
// returns a copy with the values of common secret-bearing keys replaced by
// a static marker. This is a conservative string transform (not a full YAML
// round-trip) so that it never fails on malformed input — in the worst case
// a value fails to match and remains, which is why this function is used
// only alongside the shared-token gate on the handler.
func redactAlertmanagerSecrets(y string) string {
	if y == "" {
		return y
	}
	return secretKeyRE.ReplaceAllString(y, "${1}${2}"+redactionMarker)
}

func (a *API) deactivateConfig(w http.ResponseWriter, r *http.Request) {
	userID, _, err := tenant.ExtractTenantIDFromHTTPRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	logger := util_log.WithContext(r.Context(), util_log.Logger)

	if err := a.db.DeactivateConfig(r.Context(), userID); err != nil {
		if err == sql.ErrNoRows {
			level.Info(logger).Log("msg", "deactivate config - no configuration", "userID", userID)
			http.Error(w, "No configuration", http.StatusNotFound)
			return
		}
		level.Error(logger).Log("msg", "error deactivating config", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(logger).Log("msg", "config deactivated", "userID", userID)
	w.WriteHeader(http.StatusOK)
}

func (a *API) restoreConfig(w http.ResponseWriter, r *http.Request) {
	userID, _, err := tenant.ExtractTenantIDFromHTTPRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	logger := util_log.WithContext(r.Context(), util_log.Logger)

	if err := a.db.RestoreConfig(r.Context(), userID); err != nil {
		if err == sql.ErrNoRows {
			level.Info(logger).Log("msg", "restore config - no configuration", "userID", userID)
			http.Error(w, "No configuration", http.StatusNotFound)
			return
		}
		level.Error(logger).Log("msg", "error restoring config", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	level.Info(logger).Log("msg", "config restored", "userID", userID)
	w.WriteHeader(http.StatusOK)
}

const (
	FormatInvalid = "invalid"
	FormatJSON    = "json"
	FormatYAML    = "yaml"
)

func parseConfigFormat(v string, defaultFormat string) string {
	if v == "" {
		return defaultFormat
	}
	parts := strings.Split(v, ",")
	for _, part := range parts {
		mimeType, _, err := mime.ParseMediaType(part)
		if err != nil {
			continue
		}
		switch mimeType {
		case "application/json":
			return FormatJSON
		case "text/yaml", "text/x-yaml", "application/yaml", "application/x-yaml":
			return FormatYAML
		}
	}
	return defaultFormat
}
