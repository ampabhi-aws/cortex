package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants, when > 0, is the maximum number of tenants allowed in a
	// single federated query (pipe-separated X-Scope-OrgID). Requests that
	// exceed the limit are rejected before any per-tenant queriers are
	// allocated, preventing header-driven fan-out that can exhaust
	// goroutines and connections on shared read-path components.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants that a single federated query may address via the `X-Scope-OrgID` header. 0 disables the check. When the request names more tenants than this limit, the query is rejected before any per-tenant querier is allocated, bounding the fan-out and resource amplification caused by attacker-controlled headers.")
}
