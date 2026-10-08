// Package worker request_validation enforces defence-in-depth on requests dispatched by the
// querier worker. Requests arrive from the query-frontend/query-scheduler over gRPC: the enqueue
// path on those components may not authenticate the caller (see pkg/cortex/cortex.go noGRPCAuthOn),
// so the worker treats the method, URL and headers of each HTTP request message as untrusted. The
// scheduler/frontend enqueue path is a generic HTTP dispatcher
// (vendor/github.com/weaveworks/common/httpgrpc/server/server.go) that would otherwise reach any
// route on the local mux, including auth=false admin routes such as /config, /debug/pprof/*,
// /runtime_config, /services, /memberlist, /ingester/ring and /ring.
package worker

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/weaveworks/common/httpgrpc"
)

// hopByHopHeaders are stripped from inbound worker requests. These never belong on a logical
// end-to-end query request and have historically been abused to pivot through proxies.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// adminHeaders are stripped from inbound worker requests so that a scheduler/frontend peer cannot
// spoof the ingress source IP that cortex sometimes logs. We deliberately do NOT strip X-Scope-OrgID
// here: in microservices mode the querier's AuthMiddleware reads it to inject the tenant into the
// handler's context, and the scheduler validates msg.UserID via tenant.TenantIDsFromOrgID before
// enqueueing. The path/method allowlist above is what prevents an attacker from reaching
// non-tenant-scoped admin routes; headers are only sanitised, not required for the auth control.
var adminHeaders = map[string]struct{}{
	"x-forwarded-for":  {},
	"x-forwarded-host": {},
	"x-real-ip":        {},
	"forwarded":        {},
}

// allowedWorkerMethods restricts worker requests to safe query verbs. The Prometheus query API uses
// GET and POST only; DELETE on /series is omitted deliberately because the worker is not expected to
// mutate tombstones from a scheduler-enqueued request and the operation is admin-level.
var allowedWorkerMethods = map[string]struct{}{
	http.MethodGet:  {},
	http.MethodPost: {},
}

// validateAndSanitizeWorkerRequest enforces that the inbound HTTP request message carries a safe
// method, URL path and header set. On success, the request is mutated in place to remove disallowed
// headers. On failure, a non-nil *httpgrpc.HTTPResponse is returned describing why the request was
// rejected; callers should return that response to the scheduler/frontend without invoking the
// local HTTP handler.
//
// The allowed path prefixes are supplied by the caller (populated from Config.AllowedPathPrefixes).
// If the slice is empty the request is rejected: an empty allowlist means the worker has no safe
// scope to dispatch into, which should never happen in a correctly-wired deployment.
func validateAndSanitizeWorkerRequest(req *httpgrpc.HTTPRequest, allowedPrefixes []string) *httpgrpc.HTTPResponse {
	if req == nil {
		return &httpgrpc.HTTPResponse{Code: http.StatusBadRequest, Body: []byte("empty request")}
	}

	if _, ok := allowedWorkerMethods[strings.ToUpper(req.Method)]; !ok {
		return &httpgrpc.HTTPResponse{Code: http.StatusMethodNotAllowed, Body: []byte("method not allowed")}
	}

	if len(allowedPrefixes) == 0 {
		return &httpgrpc.HTTPResponse{Code: http.StatusForbidden, Body: []byte("path not allowed")}
	}

	// Resolve the URL as the vendored httpgrpc server would (http.NewRequest). We only inspect the
	// path for the allowlist check so that query strings cannot smuggle a disallowed route.
	parsed, err := url.ParseRequestURI(req.Url)
	if err != nil {
		return &httpgrpc.HTTPResponse{Code: http.StatusBadRequest, Body: []byte("invalid URL")}
	}
	cleanPath := parsed.EscapedPath()
	if cleanPath == "" {
		cleanPath = "/"
	}

	if !hasAllowedPrefix(cleanPath, allowedPrefixes) {
		return &httpgrpc.HTTPResponse{Code: http.StatusForbidden, Body: []byte("path not allowed")}
	}

	// Strip hop-by-hop and admin headers in place. We keep the slice backing array; this is a
	// filter, not a reallocation, so the mutation is safe for the subsequent handler.Handle call.
	filtered := req.Headers[:0]
	for _, h := range req.Headers {
		if h == nil {
			continue
		}
		lk := strings.ToLower(h.Key)
		if _, drop := hopByHopHeaders[lk]; drop {
			continue
		}
		if _, drop := adminHeaders[lk]; drop {
			continue
		}
		filtered = append(filtered, h)
	}
	req.Headers = filtered

	return nil
}

func hasAllowedPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
