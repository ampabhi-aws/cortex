package client

// ClusterAdminTenantID is a reserved pseudo-tenant marker that internal
// Cortex components (e.g. the distributor) use when calling cluster-wide
// administrative RPCs on the ingester (such as AllUserStats). The ingester
// treats a request bearing this tenant ID as an operator/cluster-admin call
// and returns results covering all tenants; any other caller is scoped to
// their own tenant to avoid cross-tenant disclosure. The value is reserved
// (not a valid tenant ID in deployments following Cortex's documented
// tenant-ID conventions) and must only be injected on internal, trusted
// paths (e.g. mTLS-authenticated gRPC between Cortex components).
const ClusterAdminTenantID = "__cortex_cluster_admin__"

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
