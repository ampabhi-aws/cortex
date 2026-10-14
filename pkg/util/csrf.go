package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// CSRF is the request field, cookie name, and template placeholder used by
// the Cortex admin pages to anti-CSRF protect state-changing operations.
const (
	// CSRFTokenPlaceholder is the literal string embedded in HTML templates
	// that CSRFSubstitute replaces with the per-session token before the
	// rendered page is sent to the client.
	CSRFTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

	// CSRFFormField is the name of the form field holding the token on
	// POST requests.
	CSRFFormField = "csrf_token"

	// CSRFCookieName is the name of the cookie that pins the token to the
	// browser session.
	CSRFCookieName = "cortex_csrf_token"

	csrfTokenBytes = 32
)

// CSRFToken returns the CSRF token bound to this browser session, creating
// and setting the cookie on w if the request does not already carry one.
// The returned token is safe to embed in HTML as a hidden form field.
func CSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(CSRFCookieName); err == nil && c != nil && isValidCSRFToken(c.Value) {
		return c.Value
	}

	buf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// On the astronomically unlikely failure of crypto/rand we return
		// an empty token; CSRFValidate will then reject every POST.
		return ""
	}
	token := hex.EncodeToString(buf)

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	// Make the newly minted token visible to downstream handlers that read
	// the cookie off the current request (e.g. a redirect/render on the
	// same request).
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	return token
}

// CSRFSubstitute replaces every occurrence of CSRFTokenPlaceholder in body
// with the given token.
func CSRFSubstitute(body []byte, token string) []byte {
	if token == "" {
		return body
	}
	// strings.ReplaceAll on []byte without allocating twice.
	return []byte(strings.ReplaceAll(string(body), CSRFTokenPlaceholder, token))
}

// CSRFValidate returns true when the request carries a csrf_token form
// value that matches the token cookie bound to this browser session. The
// comparison is constant-time. A missing cookie or form field fails
// validation.
func CSRFValidate(r *http.Request) bool {
	c, err := r.Cookie(CSRFCookieName)
	if err != nil || c == nil || !isValidCSRFToken(c.Value) {
		return false
	}
	formToken := r.FormValue(CSRFFormField)
	if !isValidCSRFToken(formToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(formToken)) == 1
}

// CSRFCheckOrigin rejects state-changing requests whose Origin or
// Sec-Fetch-Site headers indicate a cross-site navigation. It returns true
// when the request is considered same-site (and the handler may proceed).
//
// The checks are:
//   - If Sec-Fetch-Site is present it must be "same-origin", "same-site" or
//     "none" (direct navigation / bookmark).
//   - If Origin is present it must share host (minus port) with the
//     Host header of the request.
//
// A request that supplies neither header (older browsers / curl) is
// accepted; the CSRF token check is still required to actually mutate.
func CSRFCheckOrigin(r *http.Request) bool {
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site":
		return false
	case "same-origin", "same-site", "none", "":
		// fall through to Origin check
	}

	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}

	oh := u.Hostname()
	rh := r.Host
	if h, _, err := net.SplitHostPort(rh); err == nil {
		rh = h
	}
	return strings.EqualFold(oh, rh)
}

func isValidCSRFToken(s string) bool {
	if len(s) != csrfTokenBytes*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
