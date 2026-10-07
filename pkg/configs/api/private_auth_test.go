package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/configs/db/dbtest"
)

// bearerRequest performs an HTTP request against app with an optional
// Authorization: Bearer token. An empty token means no header is sent.
func bearerRequest(t *testing.T, method, urlStr, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, nil)
	require.NoError(t, err)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	app.ServeHTTP(w, r)
	return w
}

// Test_PrivateEndpoints_RequireBearerToken proves that the
// /private/api/prom/configs/{rules,alertmanager} endpoints fail closed when
// the caller does not present the shared Bearer token the server is
// configured with.
func Test_PrivateEndpoints_RequireBearerToken(t *testing.T) {
	setup(t)
	defer cleanup(t)

	// Seed one config so an unauthorized caller would see data if the
	// authorization check were missing.
	userID := makeUserID()
	rulesClient.post(t, userID, makeConfig())

	for _, c := range allClients {
		w := bearerRequest(t, "GET", c.PrivateEndpoint, "")
		assert.Equal(t, http.StatusForbidden, w.Code, "missing-token request to %s should be forbidden", c.PrivateEndpoint)

		w = bearerRequest(t, "GET", c.PrivateEndpoint, "wrong-token")
		assert.Equal(t, http.StatusForbidden, w.Code, "wrong-token request to %s should be forbidden", c.PrivateEndpoint)

		w = bearerRequest(t, "GET", c.PrivateEndpoint, testToken)
		assert.Equal(t, http.StatusOK, w.Code, "valid-token request to %s should succeed", c.PrivateEndpoint)
	}
}

// Test_PrivateEndpoints_FailClosedWhenServerTokenEmpty verifies that an
// operator who forgets to configure a shared token cannot accidentally
// expose every tenant's configuration.
func Test_PrivateEndpoints_FailClosedWhenServerTokenEmpty(t *testing.T) {
	database = dbtest.Setup(t)
	defer dbtest.Cleanup(t, database)
	app = New(database, Config{}) // PrivateAPIAuthToken left empty.

	for _, c := range allClients {
		w := bearerRequest(t, "GET", c.PrivateEndpoint, "")
		assert.Equal(t, http.StatusForbidden, w.Code, "unauthenticated request to %s must be forbidden when server token is empty", c.PrivateEndpoint)

		w = bearerRequest(t, "GET", c.PrivateEndpoint, "any-value")
		assert.Equal(t, http.StatusForbidden, w.Code, "any-token request to %s must be forbidden when server token is empty", c.PrivateEndpoint)
	}
}
