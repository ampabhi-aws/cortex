package alertmanager

import (
	amconfig "github.com/prometheus/alertmanager/config"
)

// ValidateAlertmanagerConfig is the exported entry point for Cortex-wide
// Alertmanager configuration validation. It recursively walks the provided
// config and enforces the Cortex-specific deny-list for secret-source fields
// such as basic_auth.password_file, authorization.credentials_file,
// bearer_token_file, oauth2.client_secret_file, tls_config.*_file,
// slack_api_url_file and VictorOps api_key_file.
//
// It accepts either a *amconfig.Config returned by amconfig.Load or any value
// that can be reflected over (which is what the internal validator expects).
// Call sites that only have the raw YAML can use ValidateAlertmanagerConfigRaw.
func ValidateAlertmanagerConfig(cfg interface{}) error {
	return validateAlertmanagerConfig(cfg)
}

// ValidateAlertmanagerConfigRaw parses the raw Alertmanager YAML and runs the
// Cortex-wide validation on the resulting config. It is a convenience helper
// for callers that only have the raw bytes.
func ValidateAlertmanagerConfigRaw(raw string) error {
	amCfg, err := amconfig.Load(raw)
	if err != nil {
		return err
	}
	return validateAlertmanagerConfig(amCfg)
}

// ValidateTemplateFilename is the exported wrapper around the internal
// template-filename validator. It rejects any filename that contains a path
// component (including relative traversal) so a tenant cannot cause the
// Alertmanager to write template files outside of its own per-tenant
// templates directory.
func ValidateTemplateFilename(filename string) error {
	return validateTemplateFilename(filename)
}
