// Package alertcfg contains validation helpers for tenant-supplied Alertmanager
// configurations that are shared between the Alertmanager HTTP API (object-storage
// path), the deprecated configs service and the configdb alertstore backend.
//
// Centralising the recursive "*_file" denylist here ensures tenant input cannot
// bypass CVE-2021-31232/CVE-2021-36157 counter-measures depending on which API
// is used to upload the config.
package alertcfg

import (
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/pkg/errors"
	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
)

// Errors returned by Validate. They match the strings previously returned by
// pkg/alertmanager/api.go so operator-visible error messages are unchanged.
var (
	ErrPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	ErrOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	ErrTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	ErrSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	ErrVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
)

// Validate recursively scans the input Alertmanager config looking for data types
// for which we have a specific validation and, whenever encountered, runs it.
// Returns the first error or nil if validation succeeds.
//
// This is the hardened denylist introduced for CVE-2021-31232 /
// CVE-2021-36157: it rejects password_file, bearer_token_file, credentials_file,
// OAuth2 client_secret_file, TLS ca_file/cert_file/key_file, Slack api_url_file /
// global slack_api_url_file and VictorOps api_key_file.
func Validate(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if !v.IsValid() || v.IsZero() {
		return nil
	}
	t := v.Type()

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
				if err := Validate(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			fieldValue := v.Index(i)

			if fieldValue.CanInterface() {
				if err := Validate(fieldValue.Interface()); err != nil {
					return err
				}
			}
		}
	}

	if t.Kind() == reflect.Map {
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

// ValidateTemplateFilename validates the template filename and returns error if it's not valid.
// The validation done in this function is a first fence to avoid having a tenant submit
// a config which may escape the per-tenant data directory on disk.
func ValidateTemplateFilename(filename string) error {
	if filepath.Base(filename) != filename {
		return fmt.Errorf("invalid template name %q: the template name cannot contain any path", filename)
	}

	// Further enforce no path in the template name.
	if filepath.Dir(filepath.Clean(filename)) != "." {
		return fmt.Errorf("invalid template name %q: the template name cannot contain any path", filename)
	}

	return nil
}

// validateReceiverHTTPConfig validates the HTTP config and returns an error if it contains
// settings not allowed by Cortex.
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

// validateReceiverTLSConfig validates the TLS config and returns an error if it contains
// settings not allowed by Cortex.
func validateReceiverTLSConfig(cfg commoncfg.TLSConfig) error {
	if cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" {
		return ErrTLSFileNotAllowed
	}
	return nil
}

// validateGlobalConfig validates the Global config and returns an error if it contains
// settings not allowed by Cortex.
func validateGlobalConfig(cfg config.GlobalConfig) error {
	if cfg.SlackAPIURLFile != "" {
		return ErrSlackAPIURLFileNotAllowed
	}
	return nil
}

// validateSlackConfig validates the Slack config and returns an error if it contains
// settings not allowed by Cortex.
func validateSlackConfig(cfg config.SlackConfig) error {
	if cfg.APIURLFile != "" {
		return ErrSlackAPIURLFileNotAllowed
	}
	return nil
}

// validateVictorOpsConfig validates the VictorOps config and returns an error if it contains
// settings not allowed by Cortex.
func validateVictorOpsConfig(cfg config.VictorOpsConfig) error {
	if cfg.APIKeyFile != "" {
		return ErrVictorOpsAPIKeyFileNotAllowed
	}
	return nil
}
