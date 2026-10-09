package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants bounds how many tenant IDs a single request may federate
	// across. Zero disables the limit (previous behaviour).
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 10, "Maximum number of tenant IDs allowed in a single federated query request (specified via the `|` separator in the `X-Scope-OrgID` header). Requests exceeding this limit are rejected. Set to 0 to disable the limit. Bounding the tenant-set size prevents a client from inflating per-tenant queue, round-robin and shuffle-shard allocations by minting arbitrarily many sub-tenant identities.")
}
