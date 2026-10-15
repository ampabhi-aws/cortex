// Package amvalidation contains helpers for validating tenant-supplied
// Alertmanager configurations. The checks are shared between the tenant-facing
// Alertmanager HTTP API (pkg/alertmanager) and the configs service HTTP API
// (pkg/configs/api) so that both tenant write paths apply the same rejection
// rules for file-valued credential and TLS fields. The checks mirror what the
// Alertmanager will otherwise read from the Cortex process filesystem at
// notify time, which would leak those file contents to tenant-controlled
// receivers.
package amvalidation

import (
	"errors"
	"reflect"

	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
)

// Errors returned by the validation functions. They are exported so callers
// can wrap them, and so tests in multiple packages can match against the
// same sentinel values.
var (
	ErrPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	ErrOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	ErrTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	ErrSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	ErrVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
	ErrOpsGenieAPIKeyFileNotAllowed  = errors.New("setting OpsGenie api_key_file is not allowed")
)

// Validate recursively scans the input Alertmanager configuration looking for
// data types for which we have specific validations and runs them. It returns
// the first error, or nil if validation succeeds. It is safe to call with any
// value; non-struct/non-collection values are ignored.
func Validate(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if !v.IsValid() || v.IsZero() {
		return nil
	}

	// If the input is a pointer, dereference it; it can't be nil at this
	// point because IsZero would have been true.
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	// Dispatch on recognised Alertmanager config types.
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

	case reflect.TypeOf(config.OpsGenieConfig{}):
		if err := validateOpsGenieConfig(v.Interface().(config.OpsGenieConfig)); err != nil {
			return err
		}
	}

	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.FieldByIndex(field.Index)
			if fieldValue.CanInterface() {
				if err := Validate(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fieldValue := v.Index(i)
			if fieldValue.CanInterface() {
				if err := Validate(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			fieldValue := v.MapIndex(key)
			if fieldValue.CanInterface() {
				if err := Validate(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// ValidateRaw parses the raw Alertmanager YAML and runs Validate against it.
// It is a convenience for callers that only have the serialized config.
func ValidateRaw(rawCfg string) error {
	if rawCfg == "" {
		return nil
	}
	amCfg, err := config.Load(rawCfg)
	if err != nil {
		return err
	}
	return Validate(amCfg)
}

func validateReceiverHTTPConfig(cfg commoncfg.HTTPClientConfig) error {
	if cfg.BasicAuth != nil && cfg.BasicAuth.PasswordFile != "" {
		return ErrPasswordFileNotAllowed
	}
	if cfg.Authorization != nil && cfg.Authorization.CredentialsFile != "" {
		return ErrPasswordFileNotAllowed
	}
	if cfg.BearerTokenFile != "" {
		return ErrPasswordFileNotAllowed
	}
	if cfg.OAuth2 != nil && cfg.OAuth2.ClientSecretFile != "" {
		return ErrOAuth2SecretFileNotAllowed
	}
	return validateReceiverTLSConfig(cfg.TLSConfig)
}

func validateReceiverTLSConfig(cfg commoncfg.TLSConfig) error {
	if cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" {
		return ErrTLSFileNotAllowed
	}
	return nil
}

func validateGlobalConfig(cfg config.GlobalConfig) error {
	if cfg.SlackAPIURLFile != "" {
		return ErrSlackAPIURLFileNotAllowed
	}
	if cfg.OpsGenieAPIKeyFile != "" {
		return ErrOpsGenieAPIKeyFileNotAllowed
	}
	return nil
}

func validateSlackConfig(cfg config.SlackConfig) error {
	if cfg.APIURLFile != "" {
		return ErrSlackAPIURLFileNotAllowed
	}
	return nil
}

func validateVictorOpsConfig(cfg config.VictorOpsConfig) error {
	if cfg.APIKeyFile != "" {
		return ErrVictorOpsAPIKeyFileNotAllowed
	}
	return nil
}

func validateOpsGenieConfig(cfg config.OpsGenieConfig) error {
	if cfg.APIKeyFile != "" {
		return ErrOpsGenieAPIKeyFileNotAllowed
	}
	return nil
}
