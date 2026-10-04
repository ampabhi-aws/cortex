package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHasValidBearer_RejectsAnonymousAndWrongTokens verifies the gate
// used by getConfigs on /private/api/prom/configs/* so an anonymous or
// mis-credentialed caller cannot dump every tenant's rules and
// Alertmanager configuration (including receiver secrets).
func TestHasValidBearer_RejectsAnonymousAndWrongTokens(t *testing.T) {
	const expected = "s3cret-shared"

	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "no header", header: "", want: false},
		{name: "wrong scheme", header: "Basic " + expected, want: false},
		{name: "wrong token", header: "Bearer not-the-secret", want: false},
		{name: "empty token", header: "Bearer ", want: false},
		{name: "correct token", header: "Bearer " + expected, want: true},
		{name: "lower-case scheme", header: "bearer " + expected, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/private/api/prom/configs/rules", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if got := hasValidBearer(r, expected); got != tc.want {
				t.Fatalf("hasValidBearer()=%v, want %v (header=%q)", got, tc.want, tc.header)
			}
		})
	}

	// A nil/empty expected secret must never authorize a caller — the
	// handler relies on this to decide whether the server is in
	// legacy-insecure mode or has an operator-configured secret.
	r := httptest.NewRequest(http.MethodGet, "/private/api/prom/configs/rules", nil)
	r.Header.Set("Authorization", "Bearer whatever")
	if hasValidBearer(r, "") {
		t.Fatalf("hasValidBearer with empty expected must return false")
	}
}
