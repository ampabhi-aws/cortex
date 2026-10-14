package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants is the maximum number of tenants allowed in a single
	// federated query. A value of 0 or less disables the check.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed in a single federated query (the number of IDs in a `|`-separated X-Scope-OrgID header). Requests exceeding this limit are rejected with HTTP 400 before any per-tenant work is scheduled. 0 to disable the limit (not recommended on public endpoints).")
}
