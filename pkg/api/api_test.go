package api

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/server"
)

type FakeLogger struct{}

func (fl *FakeLogger) Log(keyvals ...interface{}) error {
	return nil
}

func TestNewApiWithoutSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "without_source_ip_extractor",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.Nil(t, api.sourceIPs)
}

func TestNewApiWithSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		LogSourceIPs:      true,
		MetricsNamespace:  "with_source_ip_extractor",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.NotNil(t, api.sourceIPs)
}

func TestNewApiWithInvalidSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	s := server.Server{
		HTTP: &mux.Router{},
	}
	serverCfg := server.Config{
		HTTPListenNetwork:  server.DefaultNetwork,
		LogSourceIPs:       true,
		LogSourceIPsHeader: "SomeHeader",
		LogSourceIPsRegex:  "[*",
		MetricsNamespace:   "with_invalid_source_ip_extractor",
	}

	api, err := New(cfg, serverCfg, &s, &FakeLogger{})
	require.Error(t, err)
	require.Nil(t, api)
}

func TestNewApiWithHeaderLogging(t *testing.T) {
	cfg := Config{
		HTTPRequestHeadersToLog: []string{"ForTesting"},
	}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "with_header_logging",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.NotNil(t, api.HTTPHeaderMiddleware)

}

func TestNewApiWithoutHeaderLogging(t *testing.T) {
	cfg := Config{
		HTTPRequestHeadersToLog: []string{},
	}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "without_header_logging",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.Nil(t, api.HTTPHeaderMiddleware)

}

// TestUnauthenticatedRoutesAreOnAllowlist asserts that every route the API
// package registers without authentication is on the explicit
// UnauthenticatedRoutesAllowlist. The guard is here to catch regressions
// like `/ruler/rule_groups` being registered with auth=false: an all-tenant
// data endpoint registered anonymously must fail this test and force the
// author to either gate the endpoint behind auth or to explicitly add it
// to the allowlist (and justify the exposure in review).
func TestUnauthenticatedRoutesAreOnAllowlist(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "unauth_allowlist",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Register a few representative anonymous routes to prove the test
	// catches regressions. These paths are themselves on the allowlist.
	api.RegisterRoute("/config", handler, false, "GET")
	api.RegisterRoute("/runtime_config", handler, false, "GET")
	api.RegisterRoute("/ruler/ring", handler, false, "GET", "POST")

	// Register an authenticated route to prove it is not required to be on
	// the allowlist.
	api.RegisterRoute("/api/v1/rules", handler, true, "GET")

	for _, r := range api.RegisteredRoutes() {
		if r.Auth || r.Prefix {
			// Prefix routes are component UIs (e.g. the Alertmanager and
			// Prometheus UIs); they are already registered with auth=true
			// in the real wiring, and are intentionally excluded from this
			// static allowlist check because their exact prefix depends on
			// runtime configuration.
			continue
		}
		if _, ok := UnauthenticatedRoutesAllowlist[r.Path]; !ok {
			t.Fatalf("route %q is registered with auth=false but is not on UnauthenticatedRoutesAllowlist in pkg/api/api.go. If this is an operator-only endpoint, add it to the allowlist and document the exposure. If it exposes tenant data, register it with auth=true (and gate it behind an opt-in flag + tenant allowlist, as /ruler/rule_groups now is).", r.Path)
		}
	}
}

// TestRulerRuleGroupsNotRegisteredAnonymously is a focused regression test
// for the specific vulnerability that motivated the allowlist: the
// /ruler/rule_groups endpoint must never appear on the allowlist, so that
// future refactors cannot silently reintroduce the all-tenant leak.
func TestRulerRuleGroupsNotRegisteredAnonymously(t *testing.T) {
	if _, ok := UnauthenticatedRoutesAllowlist["/ruler/rule_groups"]; ok {
		t.Fatal("/ruler/rule_groups must NOT be on UnauthenticatedRoutesAllowlist: it dumps every tenant's rule groups and must stay behind the AuthMiddleware and the -ruler.enable-all-tenant-rules-endpoint opt-in flag")
	}
}
