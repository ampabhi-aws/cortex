package alertmanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/template"
	commoncfg "github.com/prometheus/common/config"
	"gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/concurrency"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

const (
	errMarshallingYAML       = "error marshalling YAML Alertmanager config"
	errValidatingConfig      = "error validating Alertmanager config"
	errReadingConfiguration  = "unable to read the Alertmanager config"
	errStoringConfiguration  = "unable to store the Alertmanager config"
	errDeletingConfiguration = "unable to delete the Alertmanager config"
	errNoOrgID               = "unable to determine the OrgID"
	errListAllUser           = "unable to list the Alertmanager users"
	errConfigurationTooBig   = "Alertmanager configuration is too big, limit: %d bytes"
	errTooManyTemplates      = "too many templates in the configuration: %d (limit: %d)"
	errTemplateTooBig        = "template %s is too big: %d bytes (limit: %d bytes)"

	fetchConcurrency = 16
)

var (
	errPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	errOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	errTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	errSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	errVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
)

// UserConfig is used to communicate a users alertmanager configs
type UserConfig struct {
	TemplateFiles      map[string]string `yaml:"template_files"`
	AlertmanagerConfig string            `yaml:"alertmanager_config"`
}

func (am *MultitenantAlertmanager) GetUserConfig(w http.ResponseWriter, r *http.Request) {
	logger := util_log.WithContext(r.Context(), am.logger)

	userID, err := tenant.TenantID(r.Context())
	if err != nil {
		level.Error(logger).Log("msg", errNoOrgID, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errNoOrgID, err.Error()), http.StatusUnauthorized)
		return
	}

	cfg, err := am.store.GetAlertConfig(r.Context(), userID)
	if err != nil {
		if err == alertspb.ErrNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	d, err := yaml.Marshal(&UserConfig{
		TemplateFiles:      alertspb.ParseTemplates(cfg),
		AlertmanagerConfig: cfg.RawConfig,
	})

	if err != nil {
		level.Error(logger).Log("msg", errMarshallingYAML, "err", err, "user", userID)
		http.Error(w, fmt.Sprintf("%s: %s", errMarshallingYAML, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	if _, err := w.Write(d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (am *MultitenantAlertmanager) SetUserConfig(w http.ResponseWriter, r *http.Request) {
	logger := util_log.WithContext(r.Context(), am.logger)
	userID, err := tenant.TenantID(r.Context())
	if err != nil {
		level.Error(logger).Log("msg", errNoOrgID, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errNoOrgID, err.Error()), http.StatusUnauthorized)
		return
	}

	var input io.Reader
	maxConfigSize := am.limits.AlertmanagerMaxConfigSize(userID)
	if maxConfigSize > 0 {
		// LimitReader will return EOF after reading specified number of bytes. To check if
		// we have read too many bytes, allow one extra byte.
		input = io.LimitReader(r.Body, int64(maxConfigSize)+1)
	} else {
		input = r.Body
	}

	payload, err := io.ReadAll(input)
	if err != nil {
		level.Error(logger).Log("msg", errReadingConfiguration, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errReadingConfiguration, err.Error()), http.StatusBadRequest)
		return
	}

	if maxConfigSize > 0 && len(payload) > maxConfigSize {
		msg := fmt.Sprintf(errConfigurationTooBig, maxConfigSize)
		level.Warn(logger).Log("msg", msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	cfg := &UserConfig{}
	err = yaml.Unmarshal(payload, cfg)
	if err != nil {
		level.Error(logger).Log("msg", errMarshallingYAML, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errMarshallingYAML, err.Error()), http.StatusBadRequest)
		return
	}

	cfgDesc := alertspb.ToProto(cfg.AlertmanagerConfig, cfg.TemplateFiles, userID)
	if err := validateUserConfig(logger, cfgDesc, am.limits, userID); err != nil {
		level.Warn(logger).Log("msg", errValidatingConfig, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errValidatingConfig, err.Error()), http.StatusBadRequest)
		return
	}

	err = am.store.SetAlertConfig(r.Context(), cfgDesc)
	if err != nil {
		level.Error(logger).Log("msg", errStoringConfiguration, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errStoringConfiguration, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// DeleteUserConfig is exposed via user-visible API (if enabled, uses DELETE method), but also as an internal endpoint using POST method.
// Note that if no config exists for a user, StatusOK is returned.
func (am *MultitenantAlertmanager) DeleteUserConfig(w http.ResponseWriter, r *http.Request) {
	logger := util_log.WithContext(r.Context(), am.logger)
	userID, err := tenant.TenantID(r.Context())
	if err != nil {
		level.Error(logger).Log("msg", errNoOrgID, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errNoOrgID, err.Error()), http.StatusUnauthorized)
		return
	}

	err = am.store.DeleteAlertConfig(r.Context(), userID)
	if err != nil {
		level.Error(logger).Log("msg", errDeletingConfiguration, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errDeletingConfiguration, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Partially copied from: https://github.com/prometheus/alertmanager/blob/8e861c646bf67599a1704fc843c6a94d519ce312/cli/check_config.go#L65-L96
func validateUserConfig(logger log.Logger, cfg alertspb.AlertConfigDesc, limits Limits, user string) error {
	// We don't have a valid use case for empty configurations. If a tenant does not have a
	// configuration set and issue a request to the Alertmanager, we'll a) upload an empty
	// config and b) immediately start an Alertmanager instance for them if a fallback
	// configuration is provisioned.
	if cfg.RawConfig == "" {
		return fmt.Errorf("configuration provided is empty, if you'd like to remove your configuration please use the delete configuration endpoint")
	}

	amCfg, err := config.Load(cfg.RawConfig)
	if err != nil {
		return err
	}

	// Validate the config recursively scanning it.
	if err := validateAlertmanagerConfig(amCfg); err != nil {
		return err
	}

	// Validate templates referenced in the alertmanager config.
	for _, name := range amCfg.Templates {
		if err := validateTemplateFilename(name); err != nil {
			return err
		}
	}

	// Check template limits.
	if l := limits.AlertmanagerMaxTemplatesCount(user); l > 0 && len(cfg.Templates) > l {
		return fmt.Errorf(errTooManyTemplates, len(cfg.Templates), l)
	}

	if maxSize := limits.AlertmanagerMaxTemplateSize(user); maxSize > 0 {
		for _, tmpl := range cfg.Templates {
			if size := len(tmpl.GetBody()); size > maxSize {
				return fmt.Errorf(errTemplateTooBig, tmpl.GetFilename(), size, maxSize)
			}
		}
	}

	// Validate template files.
	for _, tmpl := range cfg.Templates {
		if err := validateTemplateFilename(tmpl.Filename); err != nil {
			return err
		}
	}

	// Create templates on disk in a temporary directory.
	// Note: This means the validation will succeed if we can write to tmp but
	// not to configured data dir, and on the flipside, it'll fail if we can't write
	// to tmpDir. Ignoring both cases for now as they're ultra rare but will revisit if
	// we see this in the wild.
	userTempDir, err := os.MkdirTemp("", "validate-config-"+cfg.User)
	if err != nil {
		return err
	}
	defer os.RemoveAll(userTempDir)

	for _, tmpl := range cfg.Templates {
		templateFilepath, err := safeTemplateFilepath(userTempDir, tmpl.Filename)
		if err != nil {
			level.Error(logger).Log("msg", "unable to create template file path", "err", err, "user", cfg.User)
			return err
		}

		if _, err = storeTemplateFile(templateFilepath, tmpl.Body); err != nil {
			level.Error(logger).Log("msg", "unable to store template file", "err", err, "user", cfg.User)
			return fmt.Errorf("unable to store template file '%s'", tmpl.Filename)
		}
	}

	templateFiles := make([]string, len(amCfg.Templates))
	for i, t := range amCfg.Templates {
		templateFiles[i] = filepath.Join(userTempDir, t)
	}

	_, err = template.FromGlobs(templateFiles...)
	if err != nil {
		return err
	}

	// Note: Not validating the MultitenantAlertmanager.transformConfig function as that
	// that function shouldn't break configuration. Only way it can fail is if the base
	// autoWebhookURL itself is broken. In that case, I would argue, we should accept the config
	// not reject it.

	return nil
}

func (am *MultitenantAlertmanager) ListAllConfigs(w http.ResponseWriter, r *http.Request) {
	logger := util_log.WithContext(r.Context(), am.logger)

	// This endpoint returns every tenant's Alertmanager configuration (including
	// inline receiver credentials) and is intended for cluster operators only.
	// It must be explicitly opted into via -alertmanager.enable-list-all-configs
	// so that it is not accidentally exposed on the tenant-facing listener.
	if !am.cfg.EnableListAllConfigs {
		level.Warn(logger).Log("msg", "refusing to serve /multitenant_alertmanager/configs: endpoint is disabled; enable it with -alertmanager.enable-list-all-configs=true and only expose it on an operator-only path")
		http.Error(w, "the /multitenant_alertmanager/configs endpoint is disabled; set -alertmanager.enable-list-all-configs=true to enable it on operator-only paths", http.StatusNotFound)
		return
	}

	userIDs, err := am.store.ListAllUsers(r.Context())
	if err != nil {
		level.Error(logger).Log("msg", "failed to list users of alertmanager", "err", err)
		http.Error(w, fmt.Sprintf("%s: %s", errListAllUser, err.Error()), http.StatusInternalServerError)
		return
	}

	done := make(chan struct{})
	iter := make(chan interface{})

	go func() {
		util.StreamWriteYAMLResponse(w, iter, logger)
		close(done)
	}()

	err = concurrency.ForEachUser(r.Context(), userIDs, fetchConcurrency, func(ctx context.Context, userID string) error {
		cfg, err := am.store.GetAlertConfig(ctx, userID)
		if errors.Is(err, alertspb.ErrNotFound) {
			return nil
		} else if err != nil {
			return errors.Wrapf(err, "failed to fetch alertmanager config for user %s", userID)
		}
		data := map[string]*UserConfig{
			userID: {
				TemplateFiles:      alertspb.ParseTemplates(cfg),
				AlertmanagerConfig: redactAlertmanagerConfig(cfg.RawConfig, logger),
			},
		}

		select {
		case iter <- data:
		case <-done: // stop early, if sending response has already finished
		}

		return nil
	})
	if err != nil {
		level.Error(logger).Log("msg", "failed to list all alertmanager configs", "err", err)
	}
	close(iter)
	<-done
}

// validateAlertmanagerConfig recursively scans the input config looking for data types for which
// we have a specific validation and, whenever encountered, it runs their validation. Returns the
// first error or nil if validation succeeds.
func validateAlertmanagerConfig(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	t := v.Type()

	// Skip invalid, the zero value or a nil pointer (checked by zero value).
	if !v.IsValid() || v.IsZero() {
		return nil
	}

	// If the input config is a pointer then we need to get its value.
	// At this point the pointer value can't be nil.
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
		t = v.Type()
	}

	// Check if the input config is a data type for which we have a specific validation.
	// At this point the value can't be a pointer anymore.
	switch t {
	case reflect.TypeOf(config.GlobalConfig{}):
		if err := validateGlobalConfig(v.Interface().(config.GlobalConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(commoncfg.HTTPClientConfig{}):
		if err := validateReceiverHTTPConfig(v.Interface().(commoncfg.HTTPClientConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(commoncfg.TLSConfig{}):
		if err := validateReceiverTLSConfig(v.Interface().(commoncfg.TLSConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(config.SlackConfig{}):
		if err := validateSlackConfig(v.Interface().(config.SlackConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(config.VictorOpsConfig{}):
		if err := validateVictorOpsConfig(v.Interface().(config.VictorOpsConfig)); err != nil {
			return err
		}
	}

	// If the input config is a struct, recursively iterate on all fields.
	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.FieldByIndex(field.Index)

			// Skip any field value which can't be converted to interface (eg. primitive types).
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfig(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			fieldValue := v.Index(i)

			// Skip any field value which can't be converted to interface (eg. primitive types).
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfig(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Map {
		for _, key := range v.MapKeys() {
			fieldValue := v.MapIndex(key)

			// Skip any field value which can't be converted to interface (eg. primitive types).
			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfig(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateReceiverHTTPConfig validates the HTTP config and returns an error if it contains
// settings not allowed by Cortex.
func validateReceiverHTTPConfig(cfg commoncfg.HTTPClientConfig) error {
	if cfg.BasicAuth != nil && cfg.BasicAuth.PasswordFile != "" {
		return errPasswordFileNotAllowed
	}
	if cfg.Authorization != nil && cfg.Authorization.CredentialsFile != "" {
		return errPasswordFileNotAllowed
	}
	if cfg.BearerTokenFile != "" {
		return errPasswordFileNotAllowed
	}
	if cfg.OAuth2 != nil && cfg.OAuth2.ClientSecretFile != "" {
		return errOAuth2SecretFileNotAllowed
	}
	return validateReceiverTLSConfig(cfg.TLSConfig)
}

// validateReceiverTLSConfig validates the TLS config and returns an error if it contains
// settings not allowed by Cortex.
func validateReceiverTLSConfig(cfg commoncfg.TLSConfig) error {
	if cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" {
		return errTLSFileNotAllowed
	}
	return nil
}

// validateGlobalConfig validates the Global config and returns an error if it contains
// settings now allowed by Cortex.
func validateGlobalConfig(cfg config.GlobalConfig) error {
	if cfg.SlackAPIURLFile != "" {
		return errSlackAPIURLFileNotAllowed
	}
	return nil
}

// validateSlackConfig validates the Slack config and returns an error if it contains
// settings now allowed by Cortex.
func validateSlackConfig(cfg config.SlackConfig) error {
	if cfg.APIURLFile != "" {
		return errSlackAPIURLFileNotAllowed
	}
	return nil
}

// validateVictorOpsConfig validates the VictorOps config and returns an error if it contains
// settings now allowed by Cortex.
func validateVictorOpsConfig(cfg config.VictorOpsConfig) error {
	if cfg.APIKeyFile != "" {
		return errVictorOpsAPIKeyFileNotAllowed
	}
	return nil
}

// redactedSecretValue is the placeholder written in place of inline
// credentials when serving the admin cross-tenant config dump. It matches the
// value used by flagext.Secret.MarshalYAML.
const redactedSecretValue = "********"

// secretKeyNames are YAML keys whose scalar values must be redacted before
// being echoed back to an admin caller of GET /multitenant_alertmanager/configs.
// They cover the common receiver credential and webhook fields in a tenant's
// Alertmanager YAML (Slack, PagerDuty, OpsGenie, VictorOps, webhook, SMTP, HTTP
// client auth). The scanner mandated this set.
var secretKeyNames = map[string]struct{}{
	// Slack / webhook / OpsGenie / VictorOps / PagerDuty API URLs.
	"api_url":              {},
	"slack_api_url":        {},
	"opsgenie_api_url":     {},
	"victorops_api_url":    {},
	"pagerduty_url":        {},
	"url":                  {},
	"webhook_url":          {},
	// Routing / service / API keys.
	"api_key":              {},
	"opsgenie_api_key":     {},
	"victorops_api_key":    {},
	"routing_key":          {},
	"service_key":          {},
	// HTTP client / SMTP / OAuth2 / generic auth secrets.
	"auth_password":        {},
	"auth_secret":          {},
	"api_secret":           {},
	"bearer_token":         {},
	"password":             {},
	"client_secret":        {},
	"smtp_auth_password":   {},
	"smtp_auth_secret":     {},
}

// redactAlertmanagerConfig parses a tenant's raw Alertmanager YAML and
// replaces the scalar value of any key in secretKeyNames with "********" so
// that cross-tenant admin dumps do not leak receiver credentials. If parsing
// fails the raw config is replaced wholesale by the redacted placeholder,
// never echoed verbatim (fail closed).
func redactAlertmanagerConfig(raw string, logger log.Logger) string {
	if raw == "" {
		return raw
	}
	var root yaml.MapSlice
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		level.Warn(logger).Log("msg", "failed to parse alertmanager config for redaction; returning fully-redacted placeholder", "err", err)
		return redactedSecretValue
	}
	redacted := redactYAMLSecrets(root).(yaml.MapSlice)
	out, err := yaml.Marshal(redacted)
	if err != nil {
		level.Warn(logger).Log("msg", "failed to re-marshal redacted alertmanager config; returning fully-redacted placeholder", "err", err)
		return redactedSecretValue
	}
	return string(out)
}

// redactYAMLSecrets walks a yaml.MapSlice / []interface{} tree and replaces
// the scalar value of any key listed in secretKeyNames with the redacted
// placeholder.
func redactYAMLSecrets(node interface{}) interface{} {
	switch v := node.(type) {
	case yaml.MapSlice:
		for i, item := range v {
			if key, ok := item.Key.(string); ok {
				if _, isSecret := secretKeyNames[key]; isSecret {
					if item.Value != nil && item.Value != "" {
						v[i].Value = redactedSecretValue
						continue
					}
				}
			}
			v[i].Value = redactYAMLSecrets(item.Value)
		}
		return v
	case []interface{}:
		for i, item := range v {
			v[i] = redactYAMLSecrets(item)
		}
		return v
	case map[interface{}]interface{}:
		for k, val := range v {
			if key, ok := k.(string); ok {
				if _, isSecret := secretKeyNames[key]; isSecret {
					if val != nil && val != "" {
						v[k] = redactedSecretValue
						continue
					}
				}
			}
			v[k] = redactYAMLSecrets(val)
		}
		return v
	default:
		return v
	}
}
