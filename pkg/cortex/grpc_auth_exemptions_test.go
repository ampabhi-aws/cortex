// Copyright The Cortex Authors.
//
// This test pins the set of gRPC methods that bypass the tenant-header
// (X-Scope-OrgID) interceptor configured in SetupAuthMiddleware. The
// interceptor is NOT a peer authentication control: it only copies a
// caller-supplied tenant string into the request context. Methods on this
// list are therefore served to any caller that can reach the gRPC port, so
// adding one requires an out-of-band peer-authentication control (mTLS,
// signed service credential, network policy, etc.).
//
// If this test fails because you added or removed a method, update the
// approvedGRPCAuthExemptions map below in the same change and record in
// the PR which peer-authentication control covers the new method. Do not
// rubber-stamp the diff: the reviewer must confirm the control is in
// place before merging.
package cortex

import (
	"sort"
	"testing"
)

// approvedGRPCAuthExemptions is the review-pinned snapshot of
// GRPCAuthExemptedMethods. The boolean value documents, per method, that
// an out-of-band peer-authentication control was confirmed to be in place
// at review time (true == covered by operator-provided mTLS / network
// policy / signed token on the gRPC listener). A method MUST NOT be added
// here without updating that review record.
var approvedGRPCAuthExemptions = map[string]bool{
	// Standard gRPC health probe. Tenant-less. Must be reachable from
	// kubelet / load balancer probes; operators restrict exposure via
	// network policy.
	"/grpc.health.v1.Health/Check": true,

	// Query-frontend v1 control-plane stream. Trusts the connecting
	// querier's self-asserted identity + caller-supplied per-request
	// tenant; peer authentication must be enforced out-of-band (mTLS /
	// network policy).
	"/frontend.Frontend/Process":              true,
	"/frontend.Frontend/NotifyClientShutdown": true,

	// Query-scheduler control-plane streams. Trust the caller-supplied
	// frontend identity, querier identity and per-request tenant; peer
	// authentication must be enforced out-of-band (mTLS / network
	// policy).
	"/schedulerpb.SchedulerForFrontend/FrontendLoop":         true,
	"/schedulerpb.SchedulerForQuerier/QuerierLoop":           true,
	"/schedulerpb.SchedulerForQuerier/NotifyQuerierShutdown": true,
}

// TestGRPCAuthExemptionsArePinned fails whenever GRPCAuthExemptedMethods
// drifts from approvedGRPCAuthExemptions. A failure signals that a
// reviewer must verify the new/removed method is covered by (or no longer
// requires) an out-of-band peer-authentication control before updating
// the approved map above.
func TestGRPCAuthExemptionsArePinned(t *testing.T) {
	got := map[string]struct{}{}
	for _, m := range GRPCAuthExemptedMethods {
		if _, dup := got[m]; dup {
			t.Fatalf("duplicate entry %q in GRPCAuthExemptedMethods", m)
		}
		got[m] = struct{}{}
	}

	// Detect additions: any live method not in the approved map.
	var added []string
	for m := range got {
		if _, ok := approvedGRPCAuthExemptions[m]; !ok {
			added = append(added, m)
		}
	}
	// Detect removals: any approved method no longer live.
	var removed []string
	for m := range approvedGRPCAuthExemptions {
		if _, ok := got[m]; !ok {
			removed = append(removed, m)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return
	}
	sort.Strings(added)
	sort.Strings(removed)

	t.Fatalf(
		"GRPCAuthExemptedMethods changed without updating approvedGRPCAuthExemptions.\n"+
			"  added (require a documented out-of-band peer-authentication control): %v\n"+
			"  removed: %v\n"+
			"If an addition is intentional, update approvedGRPCAuthExemptions in\n"+
			"pkg/cortex/grpc_auth_exemptions_test.go AND record in the PR which\n"+
			"peer-authentication control (mTLS, signed service token, network\n"+
			"policy, ring-membership check in the handler, etc.) covers the new\n"+
			"method. The exemption bypasses the tenant-header interceptor, which\n"+
			"is a propagation shim, not an authentication gate.",
		added, removed,
	)
}

// TestGRPCAuthExemptionsNoStaleIngesterTransferChunks guards against the
// stale /cortex.Ingester/TransferChunks entry being re-introduced. The
// method was removed from the ingester gRPC service; keeping it in the
// exemption list silently widens the list and signals the list is
// unmaintained.
func TestGRPCAuthExemptionsNoStaleIngesterTransferChunks(t *testing.T) {
	for _, m := range GRPCAuthExemptedMethods {
		if m == "/cortex.Ingester/TransferChunks" {
			t.Fatalf("/cortex.Ingester/TransferChunks is stale (the RPC no longer exists) and must not be re-added to GRPCAuthExemptedMethods")
		}
	}
}
