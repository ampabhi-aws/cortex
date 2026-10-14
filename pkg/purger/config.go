package purger

import "flag"

// Config holds configuration for the Purger module.
type Config struct {
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

// RegisterFlags registers the Purger config flags.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false,
		"Enable the admin-only POST /purger/delete_tenant endpoint. Default false. When disabled the endpoint is not registered. The endpoint is destructive and must only be reachable from an operator admin path; reverse proxies must block /purger/ for tenant traffic.")
}
