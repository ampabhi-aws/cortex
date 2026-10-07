package tenantfederation

import (
	"flag"
)

type Config struct {
	// Enabled switches on support for multi tenant query federation
	Enabled bool `yaml:"enabled"`
	// MaxTenants bounds the number of tenants that can be federated by a
	// single query. A value of 0 means no limit, but operators are strongly
	// encouraged to set this to a sensible value (for example, 10) to
	// protect queriers against resource-amplification denial-of-service
	// attacks: a federated query with N tenants fans out into roughly N
	// sub-queries, each hitting the full ingester replication set and the
	// store gateways, and per-tenant limits are evaluated per sub-query so
	// they do not bound the request as a whole. Because Cortex applies no
	// authorization to the self-asserted X-Scope-OrgID tenant list, the
	// authenticating proxy in front of Cortex must additionally restrict
	// which tenant IDs a given caller may list.
	MaxTenants int `yaml:"max_tenants"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, "tenant-federation.enabled", false, "If enabled on all Cortex services, queries can be federated across multiple tenants. The tenant IDs involved need to be specified separated by a `|` character in the `X-Scope-OrgID` header (experimental).")
	f.IntVar(&cfg.MaxTenants, "tenant-federation.max-tenants", 0, "The maximum number of tenants allowed for a single federated query. Requests with more tenants are rejected with HTTP 400 before any sub-querier is allocated. Set to 0 to disable the limit (not recommended in multi-tenant deployments). Note: Cortex applies no authorization to the self-asserted tenant list in X-Scope-OrgID, so the authenticating proxy in front of Cortex must also restrict which tenant IDs a caller may list.")
}
