package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants is the maximum number of tenants a single federated
	// X-Scope-OrgID header may contain. 0 means unlimited and preserves the
	// previous behaviour.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed in a single federated X-Scope-OrgID header (experimental). Requests exceeding this limit are rejected at the tenant resolver before any downstream fan-out. 0 to disable the limit.")
}
