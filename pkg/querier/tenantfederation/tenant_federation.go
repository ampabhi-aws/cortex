package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenant is the maximum number of tenant IDs allowed in a single
	// federated request (0 = unlimited). This bounds the fan-out produced by
	// a single HTTP request so that one caller cannot allocate an unbounded
	// number of per-tenant sub-queriers.
	MaxTenant int `yaml:"max_tenant"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenant, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed in a single federated query. Requests listing more tenant IDs than this are rejected with HTTP 422. 0 = unlimited (default).")
}
