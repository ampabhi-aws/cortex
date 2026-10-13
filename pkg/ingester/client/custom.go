package client

// AllUserStatsAdminOrgID is the sentinel X-Scope-OrgID that control-plane
// components (e.g. the distributor serving the "all user stats" admin page)
// inject when invoking the cross-tenant Ingester.AllUserStats RPC. The
// Ingester handler rejects callers that present any other tenant org ID so
// that a tenant presenting its own legitimate org ID cannot enumerate the
// usage footprint of every other tenant resident on the ingester.
//
// This is defense-in-depth on top of the deployment-level expectation that
// the ingester gRPC port is protected by an external auth proxy / mTLS.
const AllUserStatsAdminOrgID = "1"

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
