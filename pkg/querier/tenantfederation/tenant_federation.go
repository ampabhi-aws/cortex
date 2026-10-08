package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants bounds the number of tenant IDs a single federated request may
	// carry. 0 (default) means unbounded for backwards compatibility; operators
	// exposing tenant federation on an untrusted ingress should set this to a
	// small value (for example 10) to prevent N-fold query amplification.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants a single federated query request may carry in the `X-Scope-OrgID` header. 0 to disable the limit (not recommended when the API is exposed to untrusted clients). Requests exceeding the limit are rejected before any per-tenant fan-out.")
}
