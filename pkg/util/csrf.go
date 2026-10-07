// Package util provides a lightweight CSRF defense for admin HTML forms
// (ring status pages, distributor stats page) served by Cortex.
//
// The protection is defense-in-depth: Cortex is designed to run behind an
// authenticating proxy (see docs/guides/authentication-and-authorisation.md).
// This helper rejects cross-site browser-driven POSTs even when the proxy is
// not configured or when it forwards operator cookies, so that an operator
// merely visiting an attacker-controlled page cannot evict ring members or
// trigger other mutating admin actions.
package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// CSRFTokenPlaceholder is the literal marker that admin HTML templates must
// embed in their <input type="hidden" name="csrf_token" ...> field. It will
// be substituted with a per-session token at render time by InjectCSRFToken.
const CSRFTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

const (
	csrfCookieName = "cortex_admin_csrf"
	csrfFormField  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
)

// newCSRFToken returns a cryptographically random, hex-encoded 128-bit token
// suitable for use as a per-session CSRF value.
func newCSRFToken() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand on all supported platforms does not fail in practice;
		// if it ever did, we deliberately return an empty token so that the
		// subsequent constant-time compare in ValidateCSRF fails closed.
		return ""
	}
	return hex.EncodeToString(buf[:])
}

// EnsureCSRFCookie returns the CSRF token associated with this browser
// session, setting a new HttpOnly SameSite=Strict cookie if one does not
// already exist.
func EnsureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token := newCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

// InjectCSRFToken returns html with CSRFTokenPlaceholder replaced by a
// per-session token, and (if necessary) sets a cookie on w so subsequent
// POSTs can be validated. Callers should pass the rendered template output.
func InjectCSRFToken(w http.ResponseWriter, r *http.Request, html []byte) []byte {
	if !strings.Contains(string(html), CSRFTokenPlaceholder) {
		return html
	}
	token := EnsureCSRFCookie(w, r)
	return []byte(strings.ReplaceAll(string(html), CSRFTokenPlaceholder, token))
}

// ValidateCSRF enforces two independent protections against cross-site
// POSTs to admin pages:
//
//  1. The request's Origin / Referer must match the Host it was sent to
//     (same-origin), and Sec-Fetch-Site must not be "cross-site". A request
//     with no Origin, no Referer and no Sec-Fetch-Site is accepted (this
//     covers curl/API-style callers from the same network, which the
//     deployment-level authenticating proxy is responsible for gating).
//  2. If the client did present either an Origin/Referer header or a CSRF
//     cookie, then a matching csrf_token (form field or X-CSRF-Token
//     header) is also required. This blocks CSRF via a browser form POST
//     because the attacker page cannot read the victim's cookie value.
//
// It returns true if the request should be allowed to proceed. On rejection
// it writes a 403 Forbidden response and the caller must return without
// performing the mutation.
func ValidateCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete && r.Method != http.MethodPatch {
		return true
	}

	// (1) Sec-Fetch-Site: modern browsers tag cross-site navigations.
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "same-site" && sfs != "none" {
		http.Error(w, "forbidden: cross-site request", http.StatusForbidden)
		return false
	}

	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")

	// (2) If the browser sent Origin or Referer, require same host.
	if origin != "" {
		if !sameHost(origin, r.Host) {
			http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
			return false
		}
	} else if referer != "" {
		if !sameHost(referer, r.Host) {
			http.Error(w, "forbidden: cross-origin referer", http.StatusForbidden)
			return false
		}
	}

	// (3) Double-submit CSRF cookie / form-field check.
	cookie, _ := r.Cookie(csrfCookieName)
	formToken := r.FormValue(csrfFormField)
	if formToken == "" {
		formToken = r.Header.Get(csrfHeaderName)
	}

	// Require the token whenever the client is browser-like (has an Origin,
	// Referer or an existing CSRF cookie). This preserves non-browser
	// operator use via curl/scripts while blocking the drive-by POST.
	needToken := origin != "" || referer != "" || (cookie != nil && cookie.Value != "")
	if !needToken {
		return true
	}

	if cookie == nil || cookie.Value == "" || formToken == "" {
		http.Error(w, "forbidden: missing CSRF token", http.StatusForbidden)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
		http.Error(w, "forbidden: invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// sameHost returns true if rawURL has the same host:port as host.
func sameHost(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
