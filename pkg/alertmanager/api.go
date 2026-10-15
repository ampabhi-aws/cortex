package alertmanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	errSNSMissingSigV4Credentials    = errors.New("setting SNS receiver without explicit sigv4.access_key and sigv4.secret_key is not allowed: a tenant SNS receiver would otherwise be signed with the Cortex process's ambient AWS credentials")
	errSNSSigV4ProfileNotAllowed     = errors.New("setting SNS sigv4.profile is not allowed: it would reference an operator-local AWS shared credentials profile")
	errSNSSigV4RoleARNNotAllowed     = errors.New("setting SNS sigv4.role_arn is not allowed: it would make Cortex call sts:AssumeRole with the operator's AWS identity")
	errSNSAPIURLNotAllowed           = errors.New("setting SNS api_url is not allowed: it must point to the official AWS SNS service endpoint (sns.<region>.amazonaws.com), which the AWS SDK resolves automatically from sigv4.region")
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
				AlertmanagerConfig: cfg.RawConfig,
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

	case reflect.TypeOf(config.SNSConfig{}):
		if err := validateSNSConfig(v.Interface().(config.SNSConfig)); err != nil {
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

// validateSNSConfig validates the SNS config and returns an error if it contains
// settings not allowed by Cortex. The tenant-controlled SNS receiver would otherwise
// be signed with the Cortex process's ambient AWS credentials (instance role / IRSA /
// env / named profile) and sent to a tenant-controlled endpoint (api_url), acting as a
// confused deputy and leaking SigV4-signed credential material (access key ID, session
// token) to the tenant.
func validateSNSConfig(cfg config.SNSConfig) error {
	// Require explicit static sigv4 credentials. Rejecting the empty-both case
	// prevents the AWS SDK from falling back to the Cortex process's default
	// credentials chain. The upstream SigV4Config.Validate already rejects the
	// case where only one of access_key/secret_key is set.
	if cfg.Sigv4.AccessKey == "" || cfg.Sigv4.SecretKey == "" {
		return errSNSMissingSigV4Credentials
	}
	// Reject profile and role_arn: both would make the signer use operator-side
	// identity material rather than the tenant-provided static credentials.
	if cfg.Sigv4.Profile != "" {
		return errSNSSigV4ProfileNotAllowed
	}
	if cfg.Sigv4.RoleARN != "" {
		return errSNSSigV4RoleARNNotAllowed
	}
	// Constrain api_url to the official AWS SNS service endpoints. The vendored
	// notifier passes api_url directly as the AWS SDK Endpoint, so an attacker
	// controlled host would receive the SigV4-signed request. The AWS SDK
	// resolves the correct SNS endpoint from sigv4.region when api_url is
	// empty, so disallowing it entirely is the safest option. We additionally
	// permit tenants to spell the official SNS endpoint explicitly for
	// backwards compatibility.
	if cfg.APIUrl != "" {
		if err := validateSNSAPIURL(cfg.APIUrl); err != nil {
			return err
		}
	}
	return nil
}

// validateSNSAPIURL accepts only https URLs whose host is an official AWS SNS
// service endpoint, i.e. sns.<region>.amazonaws.com (including the China and
// GovCloud partitions and the FIPS variant). It rejects templates and any
// userinfo, path, query or fragment that could redirect or alter the request.
func validateSNSAPIURL(raw string) error {
	// Reject Alertmanager templating in api_url outright: templated hosts would
	// bypass this allowlist at notify time.
	if strings.ContainsAny(raw, "{}") {
		return errSNSAPIURLNotAllowed
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errSNSAPIURLNotAllowed
	}
	if u.Scheme != "https" {
		return errSNSAPIURLNotAllowed
	}
	if u.User != nil {
		return errSNSAPIURLNotAllowed
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errSNSAPIURLNotAllowed
	}
	if u.Path != "" && u.Path != "/" {
		return errSNSAPIURLNotAllowed
	}
	host := u.Hostname()
	if host == "" {
		return errSNSAPIURLNotAllowed
	}
	// Only accept the canonical AWS SNS service hostnames:
	//   sns.<region>.amazonaws.com
	//   sns-fips.<region>.amazonaws.com
	//   sns.<region>.amazonaws.com.cn
	host = strings.ToLower(host)
	switch {
	case strings.HasPrefix(host, "sns.") || strings.HasPrefix(host, "sns-fips."):
	default:
		return errSNSAPIURLNotAllowed
	}
	if !(strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")) {
		return errSNSAPIURLNotAllowed
	}
	// Require a region label between the "sns[-fips]." prefix and the AWS
	// suffix, i.e. at least 3 dot-separated labels.
	labels := strings.Split(host, ".")
	if len(labels) < 4 {
		return errSNSAPIURLNotAllowed
	}
	return nil
}
