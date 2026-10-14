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
	"github.com/cortexproject/cortex/pkg/util/flagext"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

var (
	ErrEmailNotificationsAreDisabled   = errors.New("email notifications are disabled")
	ErrWebhookNotificationsAreDisabled = errors.New("webhook notifications are disabled")
)

// Config configures Configs API
type Config struct {
	Notifications NotificationsConfig `yaml:"notifications"`
	PrivateAPI    PrivateAPIConfig    `yaml:"private_api"`
}

// NotificationsConfig configures Alertmanager notifications method.
type NotificationsConfig struct {
	DisableEmail   bool `yaml:"disable_email"`
	DisableWebHook bool `yaml:"disable_webhook"`
}

// PrivateAPIConfig configures authentication for the internal, all-tenant
// `/private/api/prom/configs/*` endpoints. These endpoints return every
// tenant's rule files and Alertmanager configuration (including notification
// credentials embedded in the Alertmanager YAML) and are intended only for the
// internal ruler/alertmanager configdb client. By default they require a
// shared-secret bearer token so that an untrusted party able to reach the
// Cortex HTTP port cannot dump all tenants' configurations.
type PrivateAPIConfig struct {
	// AuthToken is a shared secret that must be presented in the
	// `Authorization: Bearer <token>` header on every request to
	// `/private/api/prom/configs/*`. Requests without a matching token are
	// rejected with 401 Unauthorized. The matching value must be configured
	// on the ruler/alertmanager configdb client via
	// `-<prefix>configs.private-api.auth-token`.
	AuthToken flagext.Secret `yaml:"auth_token"`

	// AllowUnauthenticated disables the bearer-token check on the
	// `/private/...` endpoints. This restores the legacy, pre-fix behavior
	// where any reachable party could dump all tenants' configurations and
	// must only be enabled when the operator terminates authentication at a
	// trusted reverse proxy or binds the configs HTTP listener to a
	// network-restricted interface. The default (false) is fail-closed.
	AllowUnauthenticated bool `yaml:"allow_unauthenticated"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Notifications.DisableEmail, "configs.notifications.disable-email", false, "Disable Email notifications for Alertmanager.")
	f.BoolVar(&cfg.Notifications.DisableWebHook, "configs.notifications.disable-webhook", false, "Disable WebHook notifications for Alertmanager.")
	f.Var(&cfg.PrivateAPI.AuthToken, "configs.private-api.auth-token", "Shared-secret bearer token required on the internal /private/api/prom/configs/* endpoints that return every tenant's rules and Alertmanager configuration. The ruler/alertmanager configdb client must be configured with the same value.")
	f.BoolVar(&cfg.PrivateAPI.AllowUnauthenticated, "configs.private-api.allow-unauthenticated", false, "Allow unauthenticated access to the internal /private/api/prom/configs/* endpoints. These endpoints expose every tenant's rules and Alertmanager configuration (including embedded notification secrets); enable only when the operator terminates authentication at a trusted reverse proxy or binds the configs HTTP listener to a network-restricted interface.")
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

// RegisterRoutes registers the configs API HTTP routes with the provided Router.
func (a *API) RegisterRoutes(r *mux.Router) {
	privateGetConfigs := a.requirePrivateAuth(a.getConfigs)
	for _, route := range []struct {
		name, method, path string
		handler            http.HandlerFunc
	}{
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
		// Internal APIs. These return every tenant's configuration and are
		// gated by requirePrivateAuth (shared-secret bearer token) so that an
		// untrusted party able to reach the Cortex HTTP port cannot dump all
		// tenants' rules and Alertmanager YAML. Operators that terminate
		// authentication at a trusted reverse proxy or bind the configs HTTP
		// listener to a network-restricted interface can opt out via
		// -configs.private-api.allow-unauthenticated=true. The /private/*
		// prefix should additionally be blocked at any tenant-facing gateway.
		{"private_get_rules", "GET", "/private/api/prom/configs/rules", privateGetConfigs},
		{"private_get_alertmanager_config", "GET", "/private/api/prom/configs/alertmanager", privateGetConfigs},
	} {
		r.Handle(route.path, route.handler).Methods(route.method).Name(route.name)
	}
}

// requirePrivateAuth wraps a handler for the internal all-tenant /private/*
// endpoints and enforces that the request carries the configured shared-secret
// bearer token. The comparison is constant-time to avoid timing side channels.
// When no token is configured and AllowUnauthenticated is false (the default),
// the endpoint is disabled and returns 503 so that a misconfigured deployment
// cannot silently leak every tenant's configuration.
func (a *API) requirePrivateAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := util_log.WithContext(r.Context(), util_log.Logger)
		w.Header().Set("Cache-Control", "no-store")
		expected := a.cfg.PrivateAPI.AuthToken.Value
		if expected == "" {
			if a.cfg.PrivateAPI.AllowUnauthenticated {
				next(w, r)
				return
			}
			level.Warn(logger).Log("msg", "rejecting request to internal all-tenant configs endpoint: no auth token configured", "path", r.URL.Path)
			http.Error(w, "internal configs API disabled: set -configs.private-api.auth-token or -configs.private-api.allow-unauthenticated=true", http.StatusServiceUnavailable)
			return
		}
		const bearerPrefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, bearerPrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cortex-configs-private"`)
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(authz, bearerPrefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cortex-configs-private" error="invalid_token"`)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		next(w, r)
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

func (a *API) getConfigs(w http.ResponseWriter, r *http.Request) {
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

	view := ConfigsView{Configs: cfgs}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(view); err != nil {
		// XXX: Untested
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
