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
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/go-kit/log/level"
	"github.com/gorilla/mux"
	amconfig "github.com/prometheus/alertmanager/config"
	amtemplate "github.com/prometheus/alertmanager/template"
	commoncfg "github.com/prometheus/common/config"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

var (
	ErrEmailNotificationsAreDisabled   = errors.New("email notifications are disabled")
	ErrWebhookNotificationsAreDisabled = errors.New("webhook notifications are disabled")

	errPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	errOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	errTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	errSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	errVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
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

	// Reject tenant-specified server-side file paths (bearer_token_file,
	// password_file, credentials_file, ca_file, cert_file, key_file,
	// slack_api_url_file, api_url_file, api_key_file, oauth2.client_secret_file).
	// A tenant that could set any of these would coerce the Alertmanager into
	// reading arbitrary server-local files and exfiltrating them through
	// notification HTTP headers (CVE-2021-31232 class). The HTTP configuration
	// API in pkg/alertmanager/api.go already rejects these settings; the
	// configdb-backed path must enforce the same policy before persisting.
	if err := validateAlertmanagerConfigNoFilePaths(amCfg); err != nil {
		return err
	}

	return nil
}

// validateAlertmanagerConfigNoFilePaths recursively scans the loaded
// alertmanager config looking for data types that may reference server-side
// files and rejects any tenant-provided file path. This mirrors the policy
// implemented by pkg/alertmanager.validateAlertmanagerConfig so that
// configurations persisted through the deprecated configs service cannot be
// used to exfiltrate local files via notification HTTP clients.
func validateAlertmanagerConfigNoFilePaths(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if !v.IsValid() || v.IsZero() {
		return nil
	}

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	switch t {
	case reflect.TypeOf(amconfig.GlobalConfig{}):
		g := v.Interface().(amconfig.GlobalConfig)
		if g.SlackAPIURLFile != "" {
			return errSlackAPIURLFileNotAllowed
		}

	case reflect.TypeOf(commoncfg.HTTPClientConfig{}):
		h := v.Interface().(commoncfg.HTTPClientConfig)
		if h.BasicAuth != nil && h.BasicAuth.PasswordFile != "" {
			return errPasswordFileNotAllowed
		}
		if h.Authorization != nil && h.Authorization.CredentialsFile != "" {
			return errPasswordFileNotAllowed
		}
		if h.BearerTokenFile != "" {
			return errPasswordFileNotAllowed
		}
		if h.OAuth2 != nil && h.OAuth2.ClientSecretFile != "" {
			return errOAuth2SecretFileNotAllowed
		}
		if h.TLSConfig.CAFile != "" || h.TLSConfig.CertFile != "" || h.TLSConfig.KeyFile != "" {
			return errTLSFileNotAllowed
		}

	case reflect.TypeOf(commoncfg.TLSConfig{}):
		tls := v.Interface().(commoncfg.TLSConfig)
		if tls.CAFile != "" || tls.CertFile != "" || tls.KeyFile != "" {
			return errTLSFileNotAllowed
		}

	case reflect.TypeOf(amconfig.SlackConfig{}):
		s := v.Interface().(amconfig.SlackConfig)
		if s.APIURLFile != "" {
			return errSlackAPIURLFileNotAllowed
		}

	case reflect.TypeOf(amconfig.VictorOpsConfig{}):
		vo := v.Interface().(amconfig.VictorOpsConfig)
		if vo.APIKeyFile != "" {
			return errVictorOpsAPIKeyFileNotAllowed
		}
	}

	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.FieldByIndex(field.Index)
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFilePaths(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fieldValue := v.Index(i)
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFilePaths(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			fieldValue := v.MapIndex(key)
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFilePaths(fieldValue.Interface()); err != nil {
					return err
				}
			}
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
