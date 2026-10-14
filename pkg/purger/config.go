package purger

import "flag"

type Config struct {
	EnableTenantDeletionAPI bool `yaml:"enable_tenant_deletion_api"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.EnableTenantDeletionAPI, "purger.enable-tenant-deletion-api", false, "Enable admin tenant deletion routes.")
}
