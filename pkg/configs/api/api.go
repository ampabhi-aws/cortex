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

const (
	errConfigurationTooBig = "configuration is too big, limit: %d bytes"
	errTooManyTemplates    = "too many templates in the configuration: %d (limit: %d)"
	errTemplateTooBig      = "template %s is too big: %d bytes (limit: %d bytes)"
	errTooManyRuleGroups   = "too many rule groups in the configuration: %d (limit: %d)"
	errTooManyRulesInGroup = "rule file %s contains too many rules: %d (limit: %d)"
)

// Limits exposes the per-tenant resource limits that setConfig enforces.
// It is a strict subset of the global validation.Overrides so we don't take
// a dependency on the full validation package from this leaf package.
// A nil Limits means "no limits are enforced" (0 == unlimited) which matches
// the behavior that existed before these limits were added.
type Limits interface {
	// AlertmanagerMaxConfigSize returns the maximum size (in bytes) of a full
	// uploaded config body. 0 disables the limit.
	AlertmanagerMaxConfigSize(userID string) int
	// AlertmanagerMaxTemplatesCount returns the maximum number of template
	// files that a tenant can store. 0 disables the limit.
	AlertmanagerMaxTemplatesCount(userID string) int
	// AlertmanagerMaxTemplateSize returns the maximum size (in bytes) of a
	// single template file. 0 disables the limit.
	AlertmanagerMaxTemplateSize(userID string) int
	// RulerMaxRuleGroupsPerTenant returns the maximum number of rule groups
	// (rule files, in legacy terms) a tenant may upload. 0 disables the limit.
	RulerMaxRuleGroupsPerTenant(userID string) int
	// RulerMaxRulesPerRuleGroup returns the maximum number of rules allowed
	// in a single group/file. 0 disables the limit.
	RulerMaxRulesPerRuleGroup(userID string) int
}

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
	db     db.DB
	cfg    Config
	limits Limits
}

// New creates a new API. A nil Limits disables the per-tenant throttling
// controls, preserving the pre-existing behavior; prefer NewWithLimits in
// production so that unbounded uploads cannot exhaust shared ruler and
// alertmanager replicas.
func New(database db.DB, cfg Config) *API {
	return NewWithLimits(database, cfg, nil)
}

// NewWithLimits creates a new API bound to the given per-tenant Limits.
func NewWithLimits(database db.DB, cfg Config, limits Limits) *API {
	a := &API{
		db:     database,
		cfg:    cfg,
		limits: limits,
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
		// Internal APIs.
		{"private_get_rules", "GET", "/private/api/prom/configs/rules", a.getConfigs},
		{"private_get_alertmanager_config", "GET", "/private/api/prom/configs/alertmanager", a.getConfigs},
	} {
		r.Handle(route.path, route.handler).Methods(route.method).Name(route.name)
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

	// Bound the request body before decoding so a single tenant cannot
	// exhaust memory on the shared configs/ruler/alertmanager replicas by
	// POSTing a huge body. We reuse the Alertmanager per-tenant config size
	// limit, since this endpoint uploads the same alertmanager/template/rule
	// payloads. 0 (the default) preserves the previous unlimited behavior
	// unless an operator opts in.
	maxConfigSize := a.alertmanagerMaxConfigSize(userID)
	if maxConfigSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxConfigSize))
	}

	var cfg userconfig.Config
	switch parseConfigFormat(r.Header.Get("Content-Type"), FormatJSON) {
	case FormatJSON:
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			// XXX: Untested
			level.Error(logger).Log("msg", "error decoding json body", "err", err)
			if isRequestBodyTooLarge(err) {
				http.Error(w, fmt.Sprintf(errConfigurationTooBig, maxConfigSize), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case FormatYAML:
		if err := yaml.NewDecoder(r.Body).Decode(&cfg); err != nil {
			// XXX: Untested
			level.Error(logger).Log("msg", "error decoding yaml body", "err", err)
			if isRequestBodyTooLarge(err) {
				http.Error(w, fmt.Sprintf(errConfigurationTooBig, maxConfigSize), http.StatusRequestEntityTooLarge)
				return
			}
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
	if err := a.validateTemplateLimits(cfg, userID); err != nil {
		level.Warn(logger).Log("msg", "template limits exceeded", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.validateRuleLimits(cfg, userID); err != nil {
		level.Warn(logger).Log("msg", "rule limits exceeded", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	// Bound the body on the standalone validate endpoint too. We don't
	// require a tenant header here (callers may be probing config syntax),
	// so we fall back to the "" tenant limit which still gives operators a
	// single knob to configure.
	userID, _, _ := tenant.ExtractTenantIDFromHTTPRequest(r)
	if max := a.alertmanagerMaxConfigSize(userID); max > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(max))
	}

	cfg, err := io.ReadAll(r.Body)
	if err != nil {
		level.Error(logger).Log("msg", "error reading request body", "err", err)
		if isRequestBodyTooLarge(err) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
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

// alertmanagerMaxConfigSize returns the configured per-tenant max body size
// in bytes, or 0 if no limits are wired in (preserving legacy behavior).
func (a *API) alertmanagerMaxConfigSize(userID string) int {
	if a.limits == nil {
		return 0
	}
	return a.limits.AlertmanagerMaxConfigSize(userID)
}

// validateTemplateLimits enforces the per-tenant template count and per-file
// size caps used by the modern Alertmanager API, so the legacy configs write
// path cannot be used to bypass them.
func (a *API) validateTemplateLimits(cfg userconfig.Config, userID string) error {
	if a.limits == nil {
		return nil
	}
	if maxCount := a.limits.AlertmanagerMaxTemplatesCount(userID); maxCount > 0 && len(cfg.TemplateFiles) > maxCount {
		return fmt.Errorf(errTooManyTemplates, len(cfg.TemplateFiles), maxCount)
	}
	if maxSize := a.limits.AlertmanagerMaxTemplateSize(userID); maxSize > 0 {
		for fn, content := range cfg.TemplateFiles {
			if size := len(content); size > maxSize {
				return fmt.Errorf(errTemplateTooBig, fn, size, maxSize)
			}
		}
	}
	return nil
}

// validateRuleLimits enforces the per-tenant ruler group and per-group rule
// caps on the legacy configs write path. In the legacy configs model each
// "rules file" maps 1:1 to a rule group once parsed, so we treat the file
// count as the group count.
func (a *API) validateRuleLimits(cfg userconfig.Config, userID string) error {
	if a.limits == nil {
		return nil
	}
	if maxGroups := a.limits.RulerMaxRuleGroupsPerTenant(userID); maxGroups > 0 && len(cfg.RulesConfig.Files) > maxGroups {
		return fmt.Errorf(errTooManyRuleGroups, len(cfg.RulesConfig.Files), maxGroups)
	}
	if maxRules := a.limits.RulerMaxRulesPerRuleGroup(userID); maxRules > 0 {
		parsed, err := cfg.RulesConfig.ParseFormatted()
		if err != nil {
			// If the rules fail to parse here we would already have been
			// rejected by validateRulesFiles earlier; fall through quietly.
			return nil
		}
		for fn, rg := range parsed {
			for _, g := range rg.Groups {
				if n := len(g.Rules); n > maxRules {
					return fmt.Errorf(errTooManyRulesInGroup, fn, n, maxRules)
				}
			}
		}
	}
	return nil
}

// isRequestBodyTooLarge reports whether err was produced by
// http.MaxBytesReader rejecting an oversized body.
func isRequestBodyTooLarge(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "http: request body too large")
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
