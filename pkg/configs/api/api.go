package api

import (
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
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

var (
	ErrEmailNotificationsAreDisabled   = errors.New("email notifications are disabled")
	ErrWebhookNotificationsAreDisabled = errors.New("webhook notifications are disabled")
)

// Config configures Configs API
type Config struct {
	Notifications NotificationsConfig `yaml:"notifications"`
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

// Route describes a single configs API HTTP route.
type Route struct {
	Name    string
	Method  string
	Path    string
	Handler http.HandlerFunc
	// Auth is true when the route is a per-tenant endpoint that must be
	// wrapped by the operator-configured HTTP auth middleware so that the
	// tenant identity is set by the authenticator rather than taken from
	// the raw client-controlled X-Scope-OrgID header. It is false for the
	// admin landing page and the internal cross-tenant endpoints that
	// intentionally do not scope to a single tenant.
	Auth bool
}

// Routes returns the configs API routes, each annotated with whether it is
// a per-tenant endpoint that requires the HTTP auth middleware.
func (a *API) Routes() []Route {
	return []Route{
		{Name: "root", Method: "GET", Path: "/", Handler: a.admin, Auth: false},
		// Dedicated APIs for updating rules config. In the future, these *must*
		// be used. These are per-tenant and must be guarded by the HTTP auth
		// middleware so the tenant identity is derived from the authenticated
		// request context rather than the raw X-Scope-OrgID header.
		{Name: "get_rules", Method: "GET", Path: "/api/prom/configs/rules", Handler: a.getConfig, Auth: true},
		{Name: "set_rules", Method: "POST", Path: "/api/prom/configs/rules", Handler: a.setConfig, Auth: true},
		{Name: "get_templates", Method: "GET", Path: "/api/prom/configs/templates", Handler: a.getConfig, Auth: true},
		{Name: "set_templates", Method: "POST", Path: "/api/prom/configs/templates", Handler: a.setConfig, Auth: true},
		{Name: "get_alertmanager_config", Method: "GET", Path: "/api/prom/configs/alertmanager", Handler: a.getConfig, Auth: true},
		{Name: "set_alertmanager_config", Method: "POST", Path: "/api/prom/configs/alertmanager", Handler: a.setConfig, Auth: true},
		{Name: "validate_alertmanager_config", Method: "POST", Path: "/api/prom/configs/alertmanager/validate", Handler: a.validateAlertmanagerConfig, Auth: true},
		{Name: "deactivate_config", Method: "DELETE", Path: "/api/prom/configs/deactivate", Handler: a.deactivateConfig, Auth: true},
		{Name: "restore_config", Method: "POST", Path: "/api/prom/configs/restore", Handler: a.restoreConfig, Auth: true},
		// Internal APIs. These intentionally return configurations for all
		// tenants and must not be exposed to tenant traffic; operators are
		// expected to gate access via network policy / reverse proxy.
		{Name: "private_get_rules", Method: "GET", Path: "/private/api/prom/configs/rules", Handler: a.getConfigs, Auth: false},
		{Name: "private_get_alertmanager_config", Method: "GET", Path: "/private/api/prom/configs/alertmanager", Handler: a.getConfigs, Auth: false},
	}
}

// RegisterRoutes registers the configs API HTTP routes with the provided
// Router without applying any authentication middleware. Callers that want
// the operator-configured HTTP auth middleware to protect per-tenant
// endpoints should instead use (*pkg/api.API).RegisterConfigAPI, which
// consumes Routes() and wraps per-tenant handlers with the configured
// AuthMiddleware. This method is retained for the internal mux built by
// New() and for tests that drive the handlers directly.
func (a *API) RegisterRoutes(r *mux.Router) {
	for _, route := range a.Routes() {
		r.Handle(route.Path, route.Handler).Methods(route.Method).Name(route.Name)
	}
}

// getConfig returns the request configuration.
func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	userID, err := tenant.TenantID(r.Context())
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
	userID, err := tenant.TenantID(r.Context())
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
	userID, err := tenant.TenantID(r.Context())
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
	userID, err := tenant.TenantID(r.Context())
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
