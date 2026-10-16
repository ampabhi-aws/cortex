package client

// AllUserStatsOperatorTenantID is the reserved tenant identifier used by
// trusted internal operator callers (e.g. the distributor) when invoking the
// ingester's AllUserStats RPC. The ingester only returns the cluster-wide
// per-tenant stats to callers that present this reserved principal; any other
// value is rejected so that an arbitrary X-Scope-OrgID cannot enumerate the
// list of tenants together with their series counts and ingestion rates.
//
// The value passes tenant.ValidTenantID (so the auth middleware accepts it)
// but is reserved: no real tenant is ever created or billed under it. Attempts
// by a real tenant to spoof it still require the attacker to already have
// authenticated network access to the ingester's gRPC port, which the
// deployment model places behind an external authentication layer.
const AllUserStatsOperatorTenantID = "__system_operator__"

// ChunksCount returns the number of chunks in response.
func (m *QueryStreamResponse) ChunksCount() int {
	if len(m.Chunkseries) == 0 {
		return 0
	}

	count := 0
	for _, entry := range m.Chunkseries {
		count += len(entry.Chunks)
	}
	return count
}

// ChunksSize returns the size of all chunks in the response.
func (m *QueryStreamResponse) ChunksSize() int {
	if len(m.Chunkseries) == 0 {
		return 0
	}

	size := 0
	for _, entry := range m.Chunkseries {
		for _, chunk := range entry.Chunks {
			size += chunk.Size()
		}
	}
	return size
}
