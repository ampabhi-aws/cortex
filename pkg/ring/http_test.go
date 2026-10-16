package ring

import (
	"net/http/httptest"
	"testing"
)

func TestCheckRingForgetAllowed(t *testing.T) {
	cases := map[string]struct {
		host    string
		headers map[string]string
		wantErr bool
	}{
		"missing_confirm_header": {
			host:    "cortex.local",
			headers: map[string]string{},
			wantErr: true,
		},
		"confirm_header_only_no_origin_no_referer": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
			},
			wantErr: false,
		},
		"confirm_header_same_origin": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
				"Origin":                       "http://cortex.local",
			},
			wantErr: false,
		},
		"confirm_header_cross_origin": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
				"Origin":                       "http://evil.example",
			},
			wantErr: true,
		},
		"confirm_header_cross_referer": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
				"Referer":                      "http://evil.example/attack",
			},
			wantErr: true,
		},
		"confirm_header_same_referer": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
				"Referer":                      "http://cortex.local/ingester/ring",
			},
			wantErr: false,
		},
		"origin_null_treated_as_absent": {
			host: "cortex.local",
			headers: map[string]string{
				"X-Cortex-Ring-Forget-Confirm": "true",
				"Origin":                       "null",
			},
			wantErr: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://"+tc.host+"/ingester/ring", nil)
			req.Host = tc.host
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			err := checkRingForgetAllowed(req)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
