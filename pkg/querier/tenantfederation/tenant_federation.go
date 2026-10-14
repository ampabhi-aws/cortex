package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants is the maximum number of tenants a single federated request
	// may span. 0 disables the limit (the historical, unlimited behaviour).
	// Requests whose resolved tenant ID list exceeds MaxTenants are rejected
	// before any sub-querier is constructed.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants a single federated request may span. Requests whose tenant list in the X-Scope-OrgID header exceeds this count are rejected before any sub-querier is built. 0 disables the limit.")
}
