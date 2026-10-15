package alertmanager

import (
	amconfig "github.com/prometheus/alertmanager/config"
)

// ValidateAlertmanagerConfig runs the Cortex Alertmanager hardening deny-list
// (e.g. the *_file options forbidden by validateReceiverHTTPConfig,
// validateGlobalConfig, validateSlackConfig and validateVictorOpsConfig)
// against a raw Alertmanager configuration. It is exported so that other
// writers of the alert store (notably the legacy configs service) can enforce
// the same deny-list before persisting a tenant-provided config.
//
// It returns the first validation error encountered, or nil if the config is
// valid. A nil / empty config is treated as valid.
func ValidateAlertmanagerConfig(rawCfg string) error {
	if rawCfg == "" {
		return nil
	}
	amCfg, err := amconfig.Load(rawCfg)
	if err != nil {
		return err
	}
	if err := validateAlertmanagerConfig(amCfg); err != nil {
		return err
	}
	// Also validate template names referenced from the config.
	for _, name := range amCfg.Templates {
		if err := validateTemplateFilename(name); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTemplateFilename validates that the given template file name does
// not contain a path component, ensuring it cannot escape the per-tenant
// templates directory when written to disk.
func ValidateTemplateFilename(filename string) error {
	return validateTemplateFilename(filename)
}
