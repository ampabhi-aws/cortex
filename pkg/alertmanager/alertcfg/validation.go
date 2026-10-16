// Package alertcfg provides shared validation for tenant-authored Alertmanager
// configurations. Both the object-store-backed Alertmanager API
// (pkg/alertmanager) and the legacy configs API (pkg/configs/api) use this
// package to apply the CVE-2021-31232 local-file-read protection to the
// receiver *_file references, and to enforce the per-tenant template
// count/size limits.
package alertcfg

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
)

const (
	ErrTooManyTemplates = "too many templates in the configuration: %d (limit: %d)"
	ErrTemplateTooBig   = "template %s is too big: %d bytes (limit: %d bytes)"
)

var (
	ErrPasswordFileNotAllowed        = errors.New("setting password_file, bearer_token_file and credentials_file is not allowed")
	ErrOAuth2SecretFileNotAllowed    = errors.New("setting OAuth2 client_secret_file is not allowed")
	ErrTLSFileNotAllowed             = errors.New("setting TLS ca_file, cert_file and key_file is not allowed")
	ErrSlackAPIURLFileNotAllowed     = errors.New("setting Slack api_url_file and global slack_api_url_file is not allowed")
	ErrVictorOpsAPIKeyFileNotAllowed = errors.New("setting VictorOps api_key_file is not allowed")
)

// Validate recursively scans the input Alertmanager config looking for data
// types for which we have a specific validation and, whenever encountered, it
// runs that validation. Returns the first error or nil if validation succeeds.
func Validate(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	t := v.Type()

	if !v.IsValid() || v.IsZero() {
		return nil
	}

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
		t = v.Type()
	}

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

	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.FieldByIndex(field.Index)

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

// TemplateLimits captures the per-tenant limits enforced on template files.
// A zero value disables the corresponding limit.
type TemplateLimits struct {
	MaxCount int
	MaxSize  int
}

// Template represents a single template file to be validated against the
// template count/size limits.
type Template struct {
	Filename string
	Body     string
}

// ValidateTemplates applies the per-tenant template count/size limits.
func ValidateTemplates(templates []Template, limits TemplateLimits) error {
	if limits.MaxCount > 0 && len(templates) > limits.MaxCount {
		return fmt.Errorf(ErrTooManyTemplates, len(templates), limits.MaxCount)
	}

	if limits.MaxSize > 0 {
		for _, tmpl := range templates {
			if size := len(tmpl.Body); size > limits.MaxSize {
				return fmt.Errorf(ErrTemplateTooBig, tmpl.Filename, size, limits.MaxSize)
			}
		}
	}
	return nil
}
