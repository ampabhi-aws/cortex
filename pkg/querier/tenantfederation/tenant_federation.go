package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`

	// MaxTenants is the maximum number of tenants allowed in a single federated
	// query. A value of 0 disables the limit (not recommended in production as
	// it leaves the per-request fan-out and attacker-controlled bucket-index
	// cache growth unbounded).
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed in a single federated query (via the `X-Scope-OrgID` header). 0 to disable the limit. Setting this to a positive value is strongly recommended to bound the per-request fan-out and attacker-controlled cache growth.")
}
