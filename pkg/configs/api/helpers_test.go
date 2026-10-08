package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"

	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/configs/db/dbtest"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func flagextSecret(v string) flagext.Secret {
	return flagext.Secret{Value: v}
}

var (
	app      *API
	database db.DB
	counter  int
)

const testInternalAPIToken = "test-internal-api-token"

// setup sets up the environment for the tests.
func setup(t *testing.T) {
	database = dbtest.Setup(t)
	app = New(database, Config{
		Notifications: NotificationsConfig{
			DisableEmail: true,
		},
		EnableInternalAPI: true,
		InternalAPIToken:  flagextSecret(testInternalAPIToken),
	})
	counter = 0
}

// setup sets up the environment for the tests with email enabled.
func setupWithEmailEnabled(t *testing.T) {
	database = dbtest.Setup(t)
	app = New(database, Config{
		Notifications: NotificationsConfig{
			DisableEmail: false,
		},
		EnableInternalAPI: true,
		InternalAPIToken:  flagextSecret(testInternalAPIToken),
	})
	counter = 0
}

// setupInternalAPIDisabled sets up the environment with the internal
// /private/* API disabled, so the handler must reply 404.
func setupInternalAPIDisabled(t *testing.T) {
	database = dbtest.Setup(t)
	app = New(database, Config{
		Notifications: NotificationsConfig{
			DisableEmail: true,
		},
		EnableInternalAPI: false,
		InternalAPIToken:  flagextSecret(testInternalAPIToken),
	})
	counter = 0
}

// cleanup cleans up the environment after a test.
func cleanup(t *testing.T) {
	dbtest.Cleanup(t, database)
}

// request makes a request to the configs API.
func request(t *testing.T, method, urlStr string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, body)
	require.NoError(t, err)
	// If the request targets a /private/* endpoint, present the configured
	// shared-secret bearer token so tests exercise the authenticated path.
	if strings.HasPrefix(r.URL.Path, "/private/") {
		r.Header.Set("Authorization", "Bearer "+testInternalAPIToken)
	}
	app.ServeHTTP(w, r)
	return w
}

// requestWithoutInternalToken makes a request to the configs API without any
// Authorization header, used to confirm that the /private/* endpoints refuse
// anonymous callers.
func requestWithoutInternalToken(t *testing.T, method, urlStr string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, nil)
	require.NoError(t, err)
	app.ServeHTTP(w, r)
	return w
}

// requestWithInternalToken makes a request to the configs API with an explicit
// bearer token (which may deliberately be the wrong one), used to confirm the
// behaviour of the shared-secret check.
func requestWithInternalToken(t *testing.T, method, urlStr, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, nil)
	require.NoError(t, err)
	r.Header.Set("Authorization", "Bearer "+token)
	app.ServeHTTP(w, r)
	return w
}

// requestAsUser makes a request to the configs API as the given user.
func requestAsUser(t *testing.T, userID string, method, urlStr string, contentType string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, body)
	require.NoError(t, err)
	r = r.WithContext(user.InjectOrgID(r.Context(), userID))
	err = user.InjectOrgIDIntoHTTPRequest(r.Context(), r)
	require.NoError(t, err)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	app.ServeHTTP(w, r)
	return w
}

// makeString makes a string, guaranteed to be unique within a test.
func makeString(pattern string) string {
	counter++
	return fmt.Sprintf(pattern, counter)
}

// makeUserID makes an arbitrary user ID. Guaranteed to be unique within a test.
func makeUserID() string {
	return makeString("user%d")
}

// makeConfig makes some arbitrary configuration.
func makeConfig() userconfig.Config {
	return userconfig.Config{
		AlertmanagerConfig: makeString(`
            # Config no. %d.
            route:
              receiver: noop

            receivers:
            - name: noop`),
		RulesConfig: userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}
}

func readerFromConfig(t *testing.T, config userconfig.Config) io.Reader {
	b, err := json.Marshal(config)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// parseView parses a userconfig.View from JSON.
func parseView(t *testing.T, b []byte) userconfig.View {
	var x userconfig.View
	err := json.Unmarshal(b, &x)
	require.NoError(t, err, "Could not unmarshal JSON: %v", string(b))
	return x
}
