package ring

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression test for the unauthenticated-POST forget vulnerability:
// Ring.ServeHTTP must never mutate the ring in response to a POST request.
// The mutating "forget" verb is only reachable via the admin-authenticated
// Ring.ServeForgetHTTP handler (see pkg/api/api.go for the route wiring).
func TestRing_ServeHTTP_POST_IsReadOnly(t *testing.T) {
	// Build a Ring whose KV client is nil: if ServeHTTP were to call forget()
	// (as the pre-patch code did), it would panic/error because
	// KVClient.CAS would be invoked. By asserting 403 and no panic, we
	// prove the mutating path is unreachable from ServeHTTP.
	r := &Ring{
		key:    "test",
		logger: log.NewNopLogger(),
	}

	req := httptest.NewRequest(http.MethodPost, "/ring", strings.NewReader("forget=victim"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() {
		r.ServeHTTP(rec, req)
	})

	resp := rec.Result()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "POST to Ring.ServeHTTP must be rejected with 403")
}

// ServeForgetHTTP must refuse any method other than POST so it cannot be
// accidentally re-used as a status page or probed with a GET.
func TestRing_ServeForgetHTTP_RejectsNonPOST(t *testing.T) {
	r := &Ring{
		key:    "test",
		logger: log.NewNopLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, "/ring", nil)
	rec := httptest.NewRecorder()

	r.ServeForgetHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
}

// ServeForgetHTTP must reject an empty "forget" parameter rather than issue a
// CAS with an empty id.
func TestRing_ServeForgetHTTP_RejectsEmptyID(t *testing.T) {
	r := &Ring{
		key:    "test",
		logger: log.NewNopLogger(),
	}

	req := httptest.NewRequest(http.MethodPost, "/ring", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ServeForgetHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
}
