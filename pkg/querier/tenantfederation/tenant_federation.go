package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants, if greater than 0, limits the number of tenants a single
	// federated request is allowed to span. Requests whose X-Scope-OrgID
	// header expands to more tenant IDs than this limit are rejected with
	// an HTTP 400 before any per-tenant work is performed. 0 (the default)
	// disables the limit for backward compatibility.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "Maximum number of tenants a single federated query is allowed to span. Requests referencing more tenant IDs than this limit are rejected before any per-tenant fan-out is performed. 0 disables the limit.")
}
