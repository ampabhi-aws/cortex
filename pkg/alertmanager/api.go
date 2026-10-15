package alertmanager

import (
	"context"
	"fmt"
	"io"
	"net"
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
	errEmailSmarthostBlocked         = errors.New("email smarthost resolves to a blocked address")
	errEmailSmarthostInvalid         = errors.New("email smarthost is not a valid host:port address")
	errEmailSmarthostUnresolvable    = errors.New("email smarthost host could not be resolved")
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

	// Enforce the per-tenant receivers firewall on tenant-controlled SMTP smarthosts.
	// The vendored email notifier dials the smarthost with a bare net.Dialer, so the
	// commoncfg.WithDialContextFunc(firewallDialer.DialContext) injected into HTTP
	// integrations does not cover it. Validate the resolved address at config-upload
	// time against the same block list used by FirewallDialer so the email receiver
	// cannot be used as an SSRF primitive to loopback/private/blocked addresses.
	if err := validateEmailSmarthosts(amCfg, limits, user); err != nil {
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

// validateEmailSmarthosts enforces the per-tenant receivers firewall against SMTP
// smarthosts configured in email_configs (and global smtp_smarthost, which the
// upstream config.Load copies into each EmailConfig when email_configs[].smarthost
// is unset). It resolves the host and rejects the config if any resolved IP is
// blocked by the tenant limits (private/loopback addresses when enabled, or any of
// the configured block CIDR networks). This mirrors util_net.FirewallDialer.control
// but runs at config-upload time, because the vendored email notifier opens the
// SMTP TCP connection with a bare net.Dialer and the firewall dialer injected into
// HTTP-based integrations does not cover that path.
func validateEmailSmarthosts(cfg *config.Config, limits Limits, user string) error {
	if cfg == nil || limits == nil {
		return nil
	}

	blockPrivate := limits.AlertmanagerReceiversBlockPrivateAddresses(user)
	blockCIDRs := limits.AlertmanagerReceiversBlockCIDRNetworks(user)

	// Fast path: if the firewall is not enabled for this tenant, nothing to enforce.
	if !blockPrivate && len(blockCIDRs) == 0 {
		return nil
	}

	check := func(hp config.HostPort) error {
		if hp.String() == "" {
			// Empty smarthost: nothing to validate here. If the user still references
			// an email_config with no effective smarthost, upstream config.Load will
			// have already rejected it with "no global SMTP smarthost set".
			return nil
		}

		if hp.Host == "" || hp.Port == "" {
			return errors.Wrapf(errEmailSmarthostInvalid, "smarthost %q", hp.String())
		}

		// Resolve to IPs so we check what will actually be dialed, mirroring the
		// behaviour of FirewallDialer which runs after DNS resolution.
		ips, err := net.LookupIP(hp.Host)
		if err != nil || len(ips) == 0 {
			return errors.Wrapf(errEmailSmarthostUnresolvable, "smarthost %q", hp.String())
		}

		for _, ip := range ips {
			if blockPrivate && (isPrivateIP(ip) || isLocalIP(ip)) {
				return errors.Wrapf(errEmailSmarthostBlocked, "smarthost %q resolves to %s", hp.String(), ip)
			}
			for _, cidr := range blockCIDRs {
				if cidr.Value.Contains(ip) {
					return errors.Wrapf(errEmailSmarthostBlocked, "smarthost %q resolves to %s", hp.String(), ip)
				}
			}
		}
		return nil
	}

	// Check the global SMTP smarthost explicitly: even if no receiver inherits it
	// (e.g. all email_configs override it), validating it prevents operators from
	// relying on a stale global default being safely scoped later.
	if cfg.Global != nil {
		if err := check(cfg.Global.SMTPSmarthost); err != nil {
			return err
		}
	}

	for _, rcv := range cfg.Receivers {
		for _, ec := range rcv.EmailConfigs {
			if ec == nil {
				continue
			}
			if err := check(ec.Smarthost); err != nil {
				return err
			}
		}
	}

	return nil
}

// isLocalIP mirrors util_net.isLocal so we can reuse the FirewallDialer policy
// without importing that package here (it has no exported helper).
func isLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// isPrivateIP mirrors util_net.isPrivate (RFC 1918 for IPv4, RFC 4193 for IPv6).
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}
