package api

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// AdminAuthConfig configures the authentication required for cluster-mutating
// (destructive) admin endpoints such as the forget POST on the ring status
// pages. The default policy is deny: admin endpoints are not registered
// unless EnableAdminEndpoints is true, and the mutating method on each page
// is only served when at least one authenticator (bearer token or
// source-CIDR allowlist) is configured.
type AdminAuthConfig struct {
	EnableAdminEndpoints    bool   `yaml:"enable_admin_endpoints"`
	AdminAuthToken          string `yaml:"admin_auth_token"`
	AdminAllowedSourceCIDRs string `yaml:"admin_allowed_source_cidrs"`
}

type adminAuthMiddleware struct {
	cfg          AdminAuthConfig
	allowedCIDRs []*net.IPNet
}

func newAdminAuthMiddleware(cfg AdminAuthConfig) (*adminAuthMiddleware, error) {
	m := &adminAuthMiddleware{cfg: cfg}
	if cfg.AdminAllowedSourceCIDRs != "" {
		for _, raw := range strings.Split(cfg.AdminAllowedSourceCIDRs, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			_, cidr, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, err
			}
			m.allowedCIDRs = append(m.allowedCIDRs, cidr)
		}
	}
	return m, nil
}

func (m *adminAuthMiddleware) configured() bool {
	return m.cfg.AdminAuthToken != "" || len(m.allowedCIDRs) > 0
}

func (m *adminAuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMutatingMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !m.cfg.EnableAdminEndpoints {
			http.Error(w, "admin endpoints disabled", http.StatusForbidden)
			return
		}
		if !m.configured() {
			http.Error(w, "admin endpoints enabled but no authenticator configured", http.StatusForbidden)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if !m.authenticate(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *adminAuthMiddleware) authenticate(r *http.Request) bool {
	if len(m.allowedCIDRs) > 0 {
		ip := clientIP(r)
		if ip == nil || !cidrsContain(m.allowedCIDRs, ip) {
			return false
		}
	}
	if m.cfg.AdminAuthToken != "" {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(m.cfg.AdminAuthToken)) != 1 {
			return false
		}
	}
	return true
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func clientIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

func cidrsContain(cidrs []*net.IPNet, ip net.IP) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func sameOrigin(r *http.Request) bool {
	if fs := r.Header.Get("Sec-Fetch-Site"); fs != "" {
		return fs == "same-origin" || fs == "same-site" || fs == "none"
	}
	host := r.Host
	if origin := r.Header.Get("Origin"); origin != "" {
		return originMatchesHost(origin, host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originMatchesHost(ref, host)
	}
	return true
}

func originMatchesHost(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
