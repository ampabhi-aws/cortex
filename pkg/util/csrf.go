package util

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// CSRFTokenPlaceholder is the literal placeholder that embedded HTML templates
// use for the CSRF token value. The placeholder is substituted at response
// render time with the process-wide token (see InjectCSRFToken).
const CSRFTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

// csrfCookieName is the double-submit cookie name used by the CSRF helpers.
const csrfCookieName = "cortex_csrf_token"

// csrfToken is a process-wide random token generated at startup. The same
// value is served in a cookie (SameSite=Strict) and embedded as a hidden form
// input; a valid POST must present both. The token is also compared against
// the Origin/Referer header to block cross-site form submissions.
var csrfToken = mustGenerateCSRFToken()

func mustGenerateCSRFToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are catastrophic; fall back to a fixed-length
		// zero token rather than panicking during package init. The paired
		// Origin/Referer check still blocks cross-site attacks.
		return strings.Repeat("0", hex.EncodedLen(len(b)))
	}
	return hex.EncodeToString(b[:])
}

// CSRFToken returns the current process-wide CSRF token value.
func CSRFToken() string {
	return csrfToken
}

// SetCSRFCookie writes the CSRF cookie onto the response so that the paired
// token can be read by the browser and submitted back as a form field.
// SameSite=Strict prevents the cookie from being attached to cross-site
// requests, which complements the Origin/Referer check performed on POST.
func SetCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // read by JS form helpers in future; token is not a secret bearer
		SameSite: http.SameSiteStrictMode,
	})
}

// CheckCSRF validates the Origin/Referer header and the double-submitted CSRF
// token for the given request. It writes an HTTP 403 response and returns
// false when the request must be rejected; callers must return immediately
// without performing any state change. The caller should invoke this only
// for unsafe HTTP methods (POST, PUT, DELETE, PATCH).
func CheckCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !checkSameOrigin(r) {
		http.Error(w, "cross-origin request blocked", http.StatusForbidden)
		return false
	}
	// Prefer the header form of the token (used by API clients that cannot
	// read the cookie), fall back to the form field used by the HTML forms.
	submitted := r.Header.Get("X-CSRF-Token")
	if submitted == "" {
		submitted = r.FormValue("csrf_token")
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" || submitted == "" {
		http.Error(w, "missing CSRF token", http.StatusForbidden)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 ||
		subtle.ConstantTimeCompare([]byte(submitted), []byte(csrfToken)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// checkSameOrigin verifies that the request's Origin (or Referer, if Origin
// is absent) matches the Host header. Browsers always attach one of these on
// cross-site form POSTs, so this blocks the classic CSRF form-submission
// vector even for clients that do not send cookies.
func checkSameOrigin(r *http.Request) bool {
	for _, h := range []string{"Origin", "Referer"} {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	// Neither Origin nor Referer present. All mainstream browsers attach at
	// least one on cross-site form submissions, so a missing value here means
	// the request did not originate from a browser context we can
	// cross-origin check. Reject to be safe — API clients can supply an
	// Origin header matching Host (or use the X-CSRF-Token flow explicitly).
	return false
}

// InjectCSRFToken substitutes CSRFTokenPlaceholder in the rendered HTML with
// the current process-wide token.
func InjectCSRFToken(html []byte) []byte {
	return bytes.ReplaceAll(html, []byte(CSRFTokenPlaceholder), []byte(csrfToken))
}
