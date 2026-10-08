package querytee

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ProxyBackend_createBackendRequest_HTTPBasicAuthentication(t *testing.T) {
	tests := map[string]struct {
		clientUser   string
		clientPass   string
		backendUser  string
		backendPass  string
		expectedUser string
		expectedPass string
		expectErr    bool
	}{
		"no auth": {
			expectedUser: "",
			expectedPass: "",
		},
		"if the request is authenticated and the backend has no auth it should forward the request auth": {
			clientUser:   "marco",
			clientPass:   "marco-secret",
			expectedUser: "marco",
			expectedPass: "marco-secret",
		},
		"if the request is authenticated and the backend has only a username it should be rejected (no password-merge oracle)": {
			clientUser:  "marco",
			clientPass:  "marco-secret",
			backendUser: "backend",
			expectErr:   true,
		},
		"if the request is authenticated and the backend is authenticated it should use the backend auth": {
			clientUser:   "marco",
			clientPass:   "marco-secret",
			backendUser:  "backend",
			backendPass:  "backend-secret",
			expectedUser: "backend",
			expectedPass: "backend-secret",
		},
		"if the request is NOT authenticated and the backend is authenticated it should use the backend auth": {
			backendUser:  "backend",
			backendPass:  "backend-secret",
			expectedUser: "backend",
			expectedPass: "backend-secret",
		},
		"if the request is NOT authenticated and the backend has only a username it should be rejected": {
			backendUser: "backend",
			expectErr:   true,
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			u, err := url.Parse(fmt.Sprintf("http://%s:%s@test", testData.backendUser, testData.backendPass))
			require.NoError(t, err)

			orig := httptest.NewRequest("GET", "/test", nil)
			if testData.clientUser != "" || testData.clientPass != "" {
				orig.SetBasicAuth(testData.clientUser, testData.clientPass)
			}

			b := NewProxyBackend("test", u, time.Second, false)
			r, err := b.createBackendRequest(orig)
			if testData.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			actualUser, actualPass, _ := r.BasicAuth()
			assert.Equal(t, testData.expectedUser, actualUser)
			assert.Equal(t, testData.expectedPass, actualPass)
		})
	}
}

func Test_ProxyBackend_createBackendRequest_TenantHandling(t *testing.T) {
	u, err := url.Parse("http://user:pass@test")
	require.NoError(t, err)

	t.Run("legacy: no tenant pinning forwards client-supplied tenant", func(t *testing.T) {
		b := NewProxyBackend("test", u, time.Second, false)
		orig := httptest.NewRequest("GET", "/test", nil)
		orig.Header.Set(orgIDHeader, "attacker-chosen")

		r, err := b.createBackendRequest(orig)
		require.NoError(t, err)
		assert.Equal(t, "attacker-chosen", r.Header.Get(orgIDHeader))
	})

	t.Run("forced tenant overrides client-supplied value", func(t *testing.T) {
		b := NewProxyBackendWithTenants("test", u, time.Second, false, "pinned", nil)
		orig := httptest.NewRequest("GET", "/test", nil)
		orig.Header.Set(orgIDHeader, "attacker-chosen")

		r, err := b.createBackendRequest(orig)
		require.NoError(t, err)
		assert.Equal(t, "pinned", r.Header.Get(orgIDHeader))
	})

	t.Run("forced tenant is set even when client sent none", func(t *testing.T) {
		b := NewProxyBackendWithTenants("test", u, time.Second, false, "pinned", nil)
		orig := httptest.NewRequest("GET", "/test", nil)

		r, err := b.createBackendRequest(orig)
		require.NoError(t, err)
		assert.Equal(t, "pinned", r.Header.Get(orgIDHeader))
	})

	t.Run("allowlist permits in-list tenant", func(t *testing.T) {
		b := NewProxyBackendWithTenants("test", u, time.Second, false, "", []string{"alpha", "beta"})
		orig := httptest.NewRequest("GET", "/test", nil)
		orig.Header.Set(orgIDHeader, "alpha")

		r, err := b.createBackendRequest(orig)
		require.NoError(t, err)
		assert.Equal(t, "alpha", r.Header.Get(orgIDHeader))
	})

	t.Run("allowlist rejects out-of-list tenant", func(t *testing.T) {
		b := NewProxyBackendWithTenants("test", u, time.Second, false, "", []string{"alpha"})
		orig := httptest.NewRequest("GET", "/test", nil)
		orig.Header.Set(orgIDHeader, "victim")

		_, err := b.createBackendRequest(orig)
		require.Error(t, err)
	})

	t.Run("allowlist rejects missing tenant", func(t *testing.T) {
		b := NewProxyBackendWithTenants("test", u, time.Second, false, "", []string{"alpha"})
		orig := httptest.NewRequest("GET", "/test", nil)

		_, err := b.createBackendRequest(orig)
		require.Error(t, err)
	})
}
