package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants caps the number of tenant IDs allowed in a single federated
	// request. 0 means unlimited (keeps the previous behaviour). When the
	// request names more tenants than this limit, the querier rejects it
	// with an HTTP 400 error instead of fanning out one upstream querier
	// per tenant ID.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenant IDs that can be specified in a federated query. Requests with more tenant IDs are rejected with HTTP 400. 0 to disable the limit (default).")
}
