package alertmanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

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
	"github.com/cortexproject/cortex/pkg/util/adminauth"
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
	// Defence-in-depth: this handler aggregates data across every tenant and
	// must only run when the request has been authorised by the operator-
	// authorisation middleware. If the admin wrapping was somehow bypassed,
	// refuse to serve rather than leaking cross-tenant data.
	if !adminauth.Authorized(r.Context()) {
		level.Warn(logger).Log("msg", "refusing to list all alertmanager configs: request is not operator-authorized")
		http.Error(w, "admin authorization required", http.StatusUnauthorized)
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
				AlertmanagerConfig: redactAlertmanagerConfigYAML(cfg.RawConfig),
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

// redactedPlaceholder is the string substituted for secret-bearing values in
// cross-tenant Alertmanager config listings.
const redactedPlaceholder = "<redacted>"

// redactedSecretKeys is the set of exact keys whose scalar values are
// considered sensitive and must not be streamed from an aggregate endpoint.
var redactedSecretKeys = map[string]struct{}{
	"auth_password":    {}, // smtp_auth_password (global) and per-receiver auth_password
	"smtp_auth_password": {},
	"bearer_token":     {},
	"password":         {}, // basic_auth.password
	"secret":           {}, // generic secret (webhook, pushover)
	"routing_key":      {}, // pagerduty routing_key
	"service_key":      {}, // pagerduty service_key
	"user_key":         {}, // pushover user_key
	"token":            {}, // pushover token, webex token
	"api_url":          {}, // slack api_url, webhook_configs url under global
	"api_key":          {},
	"api_token":        {},
	"credentials":      {},
}

// redactedSecretKeySuffixes matches sensitive keys by suffix, for keys like
// "slack_api_url", "opsgenie_api_key", "victorops_api_key" and similar in
// the Alertmanager global config block.
var redactedSecretKeySuffixes = []string{
	"_api_url",
	"_api_key",
	"_api_token",
	"_auth_password",
	"_bearer_token",
	"_password",
	"_secret",
	"_token",
}

// isSecretKey reports whether a map key names a secret-bearing field that
// must be redacted before streaming a tenant's Alertmanager configuration
// from an aggregate endpoint.
func isSecretKey(key string) bool {
	if _, ok := redactedSecretKeys[key]; ok {
		return true
	}
	for _, suffix := range redactedSecretKeySuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// redactAlertmanagerConfigYAML parses an Alertmanager YAML document and
// returns an equivalent document with every secret-bearing value replaced
// by a placeholder. The structure of the document is preserved so callers
// can still see routing/receiver topology; only credential values change.
// If the input cannot be parsed as YAML we fall back to returning the
// placeholder for the entire document rather than streaming the raw secrets.
func redactAlertmanagerConfigYAML(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	var doc interface{}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		// If we cannot parse it, we must not stream it: it may still contain
		// credentials. Return a placeholder document instead.
		return redactedPlaceholder
	}
	redactYAMLNode(doc, "")
	out, err := yaml.Marshal(doc)
	if err != nil {
		return redactedPlaceholder
	}
	return string(out)
}

// redactYAMLNode walks a YAML-decoded tree (as produced by gopkg.in/yaml.v2
// into interface{}) and redacts the value of any map key classified as a
// secret by isSecretKey. The parentKey argument is used to redact entire
// http_config blocks (where sub-keys like username/credentials may carry
// credentials even when their names do not match the suffix patterns).
func redactYAMLNode(node interface{}, parentKey string) {
	switch v := node.(type) {
	case map[interface{}]interface{}:
		for k, val := range v {
			keyStr, _ := k.(string)
			if parentKey == "http_config" || parentKey == "basic_auth" || parentKey == "authorization" {
				// Any scalar inside an HTTP client or auth block is a credential.
				if _, isMap := val.(map[interface{}]interface{}); !isMap {
					if _, isSlice := val.([]interface{}); !isSlice {
						if sv, ok := val.(string); ok && sv != "" {
							v[k] = redactedPlaceholder
							continue
						}
					}
				}
			}
			if isSecretKey(keyStr) {
				switch val.(type) {
				case string:
					if val.(string) != "" {
						v[k] = redactedPlaceholder
						continue
					}
				case nil:
					// leave nil as-is
				default:
					// For non-scalar sensitive keys (e.g. http_config), keep
					// walking so nested credentials inside are redacted too.
				}
			}
			redactYAMLNode(val, keyStr)
		}
	case map[string]interface{}:
		for k, val := range v {
			if parentKey == "http_config" || parentKey == "basic_auth" || parentKey == "authorization" {
				if _, isMap := val.(map[string]interface{}); !isMap {
					if _, isSlice := val.([]interface{}); !isSlice {
						if sv, ok := val.(string); ok && sv != "" {
							v[k] = redactedPlaceholder
							continue
						}
					}
				}
			}
			if isSecretKey(k) {
				switch val.(type) {
				case string:
					if val.(string) != "" {
						v[k] = redactedPlaceholder
						continue
					}
				case nil:
				default:
				}
			}
			redactYAMLNode(val, k)
		}
	case []interface{}:
		for _, item := range v {
			redactYAMLNode(item, parentKey)
		}
	}
}
