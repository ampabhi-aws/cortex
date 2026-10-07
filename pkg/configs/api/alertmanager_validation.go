package api

import (
	"errors"
	"reflect"

	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
)

// The checks implemented here mirror the hardened Alertmanager config
// validation used by the modern POST /api/v1/alerts write path in
// pkg/alertmanager/api.go. They are duplicated into this package so that
// the legacy configs-service write path (POST /api/prom/configs/alertmanager)
// enforces the same restrictions on secret-file / local-file references.
// Without this, an authenticated tenant could use the legacy endpoint to
// submit an Alertmanager configuration that references arbitrary local
// files (e.g. password_file, bearer_token_file, credentials_file, OAuth2
// client_secret_file, TLS ca/cert/key_file, Slack api_url_file, VictorOps
// api_key_file) and later cause the Alertmanager process to read those
// files at notification time, exfiltrating their contents to a
// tenant-controlled receiver URL.
var (
	errPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	errOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	errTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	errSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	errVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
)

// validateAlertmanagerConfigNoFileRefs recursively scans the input config
// looking for data types for which we have a specific validation and,
// whenever encountered, it runs their validation. Returns the first error
// or nil if validation succeeds. This mirrors
// pkg/alertmanager.validateAlertmanagerConfig.
func validateAlertmanagerConfigNoFileRefs(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if !v.IsValid() || v.IsZero() {
		return nil
	}

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	switch t {
	case reflect.TypeOf(config.GlobalConfig{}):
		if err := validateGlobalConfigNoFileRefs(v.Interface().(config.GlobalConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(commoncfg.HTTPClientConfig{}):
		if err := validateReceiverHTTPConfigNoFileRefs(v.Interface().(commoncfg.HTTPClientConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(commoncfg.TLSConfig{}):
		if err := validateReceiverTLSConfigNoFileRefs(v.Interface().(commoncfg.TLSConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(config.SlackConfig{}):
		if err := validateSlackConfigNoFileRefs(v.Interface().(config.SlackConfig)); err != nil {
			return err
		}

	case reflect.TypeOf(config.VictorOpsConfig{}):
		if err := validateVictorOpsConfigNoFileRefs(v.Interface().(config.VictorOpsConfig)); err != nil {
			return err
		}
	}

	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.FieldByIndex(field.Index)

			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFileRefs(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			fieldValue := v.Index(i)

			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFileRefs(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Map {
		for _, key := range v.MapKeys() {
			fieldValue := v.MapIndex(key)

			if fieldValue.CanInterface() {
				if err := validateAlertmanagerConfigNoFileRefs(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func validateReceiverHTTPConfigNoFileRefs(cfg commoncfg.HTTPClientConfig) error {
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
	return validateReceiverTLSConfigNoFileRefs(cfg.TLSConfig)
}

func validateReceiverTLSConfigNoFileRefs(cfg commoncfg.TLSConfig) error {
	if cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" {
		return errTLSFileNotAllowed
	}
	return nil
}

func validateGlobalConfigNoFileRefs(cfg config.GlobalConfig) error {
	if cfg.SlackAPIURLFile != "" {
		return errSlackAPIURLFileNotAllowed
	}
	return nil
}

func validateSlackConfigNoFileRefs(cfg config.SlackConfig) error {
	if cfg.APIURLFile != "" {
		return errSlackAPIURLFileNotAllowed
	}
	return nil
}

func validateVictorOpsConfigNoFileRefs(cfg config.VictorOpsConfig) error {
	if cfg.APIKeyFile != "" {
		return errVictorOpsAPIKeyFileNotAllowed
	}
	return nil
}
