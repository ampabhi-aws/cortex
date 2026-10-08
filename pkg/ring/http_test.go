package ring

import (
	"net/http/httptest"
	"testing"
)

func TestSameOriginRequest(t *testing.T) {
	tests := map[string]struct {
		method        string
		host          string
		origin        string
		secFetchSite  string
		expectAllowed bool
	}{
		"no Origin, no Sec-Fetch-Site is allowed (non-browser client)": {
			host:          "cortex.example:9009",
			expectAllowed: true,
		},
		"matching Origin is allowed": {
			host:          "cortex.example:9009",
			origin:        "http://cortex.example:9009",
			expectAllowed: true,
		},
		"matching Origin, Sec-Fetch-Site same-origin is allowed": {
			host:          "cortex.example:9009",
			origin:        "http://cortex.example:9009",
			secFetchSite:  "same-origin",
			expectAllowed: true,
		},
		"Sec-Fetch-Site none (user-initiated) is allowed": {
			host:          "cortex.example:9009",
			secFetchSite:  "none",
			expectAllowed: true,
		},
		"cross-site Origin is rejected": {
			host:          "cortex.example:9009",
			origin:        "https://evil.example",
			expectAllowed: false,
		},
		"Sec-Fetch-Site cross-site is rejected": {
			host:          "cortex.example:9009",
			origin:        "http://cortex.example:9009",
			secFetchSite:  "cross-site",
			expectAllowed: false,
		},
		"Sec-Fetch-Site same-site is rejected": {
			host:          "cortex.example:9009",
			secFetchSite:  "same-site",
			expectAllowed: false,
		},
		"malformed Origin is rejected": {
			host:          "cortex.example:9009",
			origin:        "not a url",
			expectAllowed: false,
		},
		"Origin host-mismatch is rejected": {
			host:          "cortex.example:9009",
			origin:        "http://cortex.example:9010",
			expectAllowed: false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ingester/ring", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			got := sameOriginRequest(req)
			if got != tc.expectAllowed {
				t.Fatalf("sameOriginRequest=%v, want %v", got, tc.expectAllowed)
			}
		})
	}
}
