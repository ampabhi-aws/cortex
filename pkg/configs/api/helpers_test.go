package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"

	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/configs/db/dbtest"
)

var (
	app      *API
	database db.DB
	counter  int
)

// setup sets up the environment for the tests.
func setup(t *testing.T) {
	database = dbtest.Setup(t)
	app = New(database, Config{
		Notifications: NotificationsConfig{
			DisableEmail: true,
		},
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
	app.ServeHTTP(w, r)
	return w
}

// requestAsUser makes a request to the configs API as the given user.
func requestAsUser(t *testing.T, userID string, method, urlStr string, contentType string, body io.Reader) *httptest.ResponseRecorder {
	return requestAsUserWithHeaders(t, userID, method, urlStr, contentType, nil, body)
}

// requestAsUserWithHeaders makes a request to the configs API as the given
// user, optionally setting additional HTTP headers (e.g. If-Match for
// optimistic concurrency on writes).
func requestAsUserWithHeaders(t *testing.T, userID string, method, urlStr string, contentType string, headers map[string]string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(method, urlStr, body)
	require.NoError(t, err)
	r = r.WithContext(user.InjectOrgID(r.Context(), userID))
	err = user.InjectOrgIDIntoHTTPRequest(r.Context(), r)
	require.NoError(t, err)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
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
