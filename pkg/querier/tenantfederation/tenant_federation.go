package tenantfederation

import (
	"flag"

	"github.com/cortexproject/cortex/pkg/tenant"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenantIDs caps the number of tenant IDs accepted in a single
	// X-Scope-OrgID header. A value of zero or less falls back to the
	// resolver compiled default.
	MaxTenantIDs int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenantIDs, "tenant-federation.max-tenants", 0, "Maximum number of tenant IDs accepted in a single X-Scope-OrgID header. Requests with more IDs are rejected instead of fanning out. A value of zero or less uses the compiled default.")
}

// Apply propagates the configured limits to the tenant package so that every
// resolver call enforces them. It must be invoked once during process startup,
// before any query path begins resolving tenant IDs.
func (cfg *Config) Apply() {
	if cfg.MaxTenantIDs > 0 {
		tenant.SetMaxTenantIDs(cfg.MaxTenantIDs)
	}
}
