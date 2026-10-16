package client

// OperatorOrgID is the reserved pseudo-tenant identifier that components
// internal to Cortex (notably the distributor) must present in order to
// request a cross-tenant aggregation from the ingester (e.g. AllUserStats).
//
// The ingester gRPC service is a trusted component-to-component interface:
// X-Scope-OrgID is accepted as-is by ServerUserHeaderInterceptor and no
// credential is verified at this layer. Using a dedicated sentinel instead
// of any tenant-settable value prevents a tenant from enumerating
// co-tenants merely by setting their own X-Scope-OrgID. Operators that
// expose cross-tenant aggregations outside the trust boundary (e.g. the
// distributor's /distributor/all_user_stats admin page) remain responsible
// for restricting them with their external authenticating proxy; the
// sentinel is not a substitute for that proxy, only a defence-in-depth
// that denies the fan-out to arbitrary tenant callers by default.
const OperatorOrgID = "__operator__"

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
