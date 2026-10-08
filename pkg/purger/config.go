package purger

import "flag"

// Config holds configuration for the purger package.
type Config struct {
	// EnableTenantDeletionAPI controls whether the /purger/delete_tenant
	// endpoint is registered. Default: false.
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

// RegisterFlags registers the flags for the purger package.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false,
		"When true, exposes the /purger/delete_tenant admin endpoint. "+
			"Operators are responsible for gating this route at the deployment layer "+
			"so it is not reachable by tenants. Default is false.")
}
