package util_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cortexproject/cortex/pkg/util"
)

func TestValidateCSRF_AllowsGET(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	assert.True(t, util.ValidateCSRF(w, req))
}

func TestValidateCSRF_AllowsPOSTWithoutBrowserSignals(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))
	assert.True(t, util.ValidateCSRF(w, req))
}

func TestValidateCSRF_RejectsCrossSiteSecFetch(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	assert.False(t, util.ValidateCSRF(w, req))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateCSRF_RejectsCrossOriginHeader(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://cortex.local/x", strings.NewReader(""))
	req.Host = "cortex.local"
	req.Header.Set("Origin", "http://attacker.example")
	assert.False(t, util.ValidateCSRF(w, req))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateCSRF_RequiresTokenWhenBrowserLike(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://cortex.local/x", strings.NewReader(""))
	req.Host = "cortex.local"
	req.Header.Set("Origin", "http://cortex.local")
	assert.False(t, util.ValidateCSRF(w, req))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateCSRF_AcceptsMatchingDoubleSubmit(t *testing.T) {
	getRecorder := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "http://cortex.local/x", nil)
	token := util.EnsureCSRFCookie(getRecorder, getReq)
	assert.NotEmpty(t, token)

	form := url.Values{}
	form.Set("csrf_token", token)
	form.Set("forget", "node-1")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://cortex.local/x", strings.NewReader(form.Encode()))
	req.Host = "cortex.local"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://cortex.local")
	req.AddCookie(&http.Cookie{Name: "cortex_admin_csrf", Value: token})
	assert.True(t, util.ValidateCSRF(w, req))
}

func TestValidateCSRF_RejectsMismatchedToken(t *testing.T) {
	form := url.Values{}
	form.Set("csrf_token", "AAA")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://cortex.local/x", strings.NewReader(form.Encode()))
	req.Host = "cortex.local"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://cortex.local")
	req.AddCookie(&http.Cookie{Name: "cortex_admin_csrf", Value: "BBB"})
	assert.False(t, util.ValidateCSRF(w, req))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestInjectCSRFToken_SubstitutesPlaceholder(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	html := []byte("<form>" + util.CSRFTokenPlaceholder + "</form>")
	out := util.InjectCSRFToken(w, req, html)
	assert.NotContains(t, string(out), util.CSRFTokenPlaceholder)
	resp := w.Result()
	cookies := resp.Cookies()
	assert.NotEmpty(t, cookies)
}
