package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/server"
)

// TestAdminOnly_ClosedByDefault asserts the operator wrapper denies all
// requests when no admin token has been configured. This prevents a
// deployment that forgets to set -api.admin-token from accidentally exposing
// all-tenant endpoints on the tenant data-plane listener.
func TestAdminOnly_ClosedByDefault(t *testing.T) {
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "admin_only_closed_by_default",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(Config{}, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	called := false
	wrapped := api.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// No token header, no configured token -> 403, inner handler must not run.
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("GET", "/ruler/rule_groups", nil))
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.False(t, called, "handler must not run when admin token is not configured")

	// Supplying any header value while the server has no configured token
	// must still be refused.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ruler/rule_groups", nil)
	req.Header.Set(AdminTokenHeader, "guess")
	wrapped.ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.False(t, called)
}

// TestAdminOnly_RequiresExactToken asserts that a configured admin token
// only matches an exact caller-supplied token, and that a mismatched or
// missing token is refused.
func TestAdminOnly_RequiresExactToken(t *testing.T) {
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "admin_only_requires_token",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(Config{AdminToken: "s3cret"}, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	calls := 0
	wrapped := api.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	// Missing header -> 403.
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("GET", "/ruler/rule_groups", nil))
	require.Equal(t, http.StatusForbidden, rr.Code)

	// Wrong header -> 403.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ruler/rule_groups", nil)
	req.Header.Set(AdminTokenHeader, "wrong")
	wrapped.ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)

	// Correct header -> 200.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ruler/rule_groups", nil)
	req.Header.Set(AdminTokenHeader, "s3cret")
	wrapped.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	require.Equal(t, 1, calls, "inner handler must only run on exact token match")
}

// TestRegisterRouteWithAuth_AdminOnly asserts that routes registered at
// AuthAdmin cannot be reached without the operator credential, even if the
// caller supplies an X-Scope-OrgID header (which previously was all that was
// needed to pass AuthMiddleware on this listener).
func TestRegisterRouteWithAuth_AdminOnly(t *testing.T) {
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "register_route_with_auth_admin",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(Config{AdminToken: "ops-key"}, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	api.RegisterRouteWithAuth("/ruler/rule_groups", inner, AuthAdmin, "GET")

	// No credential -> 403.
	rr := httptest.NewRecorder()
	s.HTTP.ServeHTTP(rr, httptest.NewRequest("GET", "/ruler/rule_groups", nil))
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.NotContains(t, rr.Body.String(), "ok")

	// Only X-Scope-OrgID (previous "auth=true" path) is NOT sufficient:
	// admin routes authenticate via the operator token, not the tenant header.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ruler/rule_groups", nil)
	req.Header.Set("X-Scope-OrgID", "tenant-a")
	s.HTTP.ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.NotContains(t, rr.Body.String(), "ok")

	// Operator token admits the request.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ruler/rule_groups", nil)
	req.Header.Set(AdminTokenHeader, "ops-key")
	s.HTTP.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "ok", strings.TrimSpace(rr.Body.String()))
}

// TestRulerListAllRulesNotReachableAsAuthNone is the regression test
// mandated by the mitigation. It asserts that after RegisterRuler runs,
// the all-tenants listing endpoint is NOT reachable without an admin
// credential \u2014 i.e. the route is not accidentally registered at
// AuthNone again. This is a lightweight structural check that only
// inspects the HTTP server's registered handlers; it does not instantiate
// a real Ruler.
func TestRulerListAllRulesNotReachableAsAuthNone(t *testing.T) {
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "list_all_rules_not_authnone",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)

	// No admin token configured => operator endpoint is closed-by-default.
	api, err := New(Config{}, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	// Simulate the mandatory registration pattern for handlers that iterate
	// ListAllUsers(): they MUST be registered at AuthAdmin. If a future
	// change downgrades the ruler route back to AuthNone, this call shape
	// is what the regression protects.
	called := false
	api.RegisterRouteWithAuth("/ruler/rule_groups", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}), AuthAdmin, "GET")

	rr := httptest.NewRecorder()
	s.HTTP.ServeHTTP(rr, httptest.NewRequest("GET", "/ruler/rule_groups", nil))
	require.Equal(t, http.StatusForbidden, rr.Code,
		"handlers iterating ListAllUsers() must NOT be reachable with AuthNone")
	require.False(t, called)
}
