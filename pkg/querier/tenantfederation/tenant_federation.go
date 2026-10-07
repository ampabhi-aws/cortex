package tenantfederation

import (
	"flag"
)

// DefaultMaxTenants is the default per-request federation fan-out cap applied
// when tenant-federation is enabled.
const DefaultMaxTenants = 10

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants caps the number of tenant IDs that can be federated in a
	// single request. 0 means unbounded (not recommended).
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", DefaultMaxTenants, "The maximum number of tenant IDs that may be federated in a single request. 0 disables the limit (not recommended: an unbounded tenant list enables per-request fan-out DoS).")
}
