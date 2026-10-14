package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants is the maximum number of tenants a single federated query may
	// address via the `X-Scope-OrgID` header. 0 (the default) disables the
	// limit. When set, requests whose resolved tenant list exceeds this value
	// are rejected before any sub-querier is created, bounding the fan-out
	// amplification against the read path.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants that a federated query is allowed to address. Requests whose resolved tenant list exceeds this value are rejected. 0 to disable the limit.")
}
