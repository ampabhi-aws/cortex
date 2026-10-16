package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`

	// MaxTenants is the maximum number of tenants allowed in a single
	// federated query. 0 means unlimited (default, backward compatible).
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed in a single federated query (0 to disable the limit). Requests whose X-Scope-OrgID header resolves to more tenant IDs than this cap are rejected before any per-tenant querier is created.")
}
