package ring

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-kit/log/level"
)

// EnableDangerousAdminEndpoints controls whether the destructive POST actions
// on the ring status pages (currently: unregister/forget an instance from the
// hash ring) are accepted. It is disabled by default because any client that
// can reach the Cortex HTTP port can otherwise mutate the shared ring, which
// can cause write failures and data loss. Operators who intentionally expose
// these pages behind an authenticated reverse proxy can opt back in by
// calling SetDangerousAdminEndpointsEnabled(true) (for example from a
// command-line flag).
var enableDangerousAdminEndpoints int32

// SetDangerousAdminEndpointsEnabled toggles acceptance of destructive POST
// actions on the ring pages. See enableDangerousAdminEndpoints for the
// rationale behind defaulting to disabled.
func SetDangerousAdminEndpointsEnabled(enabled bool) {
	var v int32
	if enabled {
		v = 1
	}
	atomic.StoreInt32(&enableDangerousAdminEndpoints, v)
}

// DangerousAdminEndpointsEnabled reports the current setting.
func DangerousAdminEndpointsEnabled() bool {
	return atomic.LoadInt32(&enableDangerousAdminEndpoints) == 1
}

// csrfTokenCookieName is the cookie that pins the per-session CSRF token used
// by the double-submit check on the ring forget form.
const csrfTokenCookieName = "cortex_ring_csrf"

// csrfTokenPlaceholder is the sentinel the HTML template emits in place of a
// real CSRF token. renderHTTPResponse replaces it with a freshly minted token
// (and sets the matching cookie) just before writing the response, so each GET
// of the page issues a usable token without changing the template contract.
const csrfTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

func newCSRFToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func verifyCSRF(req *http.Request) error {
	cookie, err := req.Cookie(csrfTokenCookieName)
	if err != nil || cookie.Value == "" {
		return fmt.Errorf("missing CSRF cookie")
	}
	formToken := req.FormValue("csrf_token")
	if formToken == "" {
		return fmt.Errorf("missing csrf_token form field")
	}
	if subtle.ConstantTimeCompare([]byte(formToken), []byte(cookie.Value)) != 1 {
		return fmt.Errorf("CSRF token mismatch")
	}
	return nil
}

const pageContent = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Ring Status</title>
	</head>
	<body>
		<h1>Ring Status</h1>
		<p>Current time: {{ .Now }}</p>
		<form action="" method="POST">
			<input type="hidden" name="csrf_token" value="$__CSRF_TOKEN_PLACEHOLDER__">
			<table width="100%" border="1">
				<thead>
					<tr>
						<th>Instance ID</th>
						<th>Availability Zone</th>
						<th>State</th>
						<th>Address</th>
						<th>Registered At</th>
						<th>Last Heartbeat</th>
						<th>Tokens</th>
						<th>Ownership</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{{ range $i, $ing := .Ingesters }}
					{{ if mod $i 2 }}
					<tr>
					{{ else }}
					<tr bgcolor="#BEBEBE">
					{{ end }}
						<td>{{ .ID }}</td>
						<td>{{ .Zone }}</td>
						<td>{{ .State }}</td>
						<td>{{ .Address }}</td>
						<td>{{ .RegisteredTimestamp }}</td>
						<td>{{ .HeartbeatTimestamp }}</td>
						<td>{{ .NumTokens }}</td>
						<td>{{ .Ownership }}%</td>
						<td><button name="forget" value="{{ .ID }}" type="submit">Forget</button></td>
					</tr>
					{{ end }}
				</tbody>
			</table>
			<br>
			{{ if .ShowTokens }}
			<input type="button" value="Hide Tokens" onclick="window.location.href = '?tokens=false' " />
			{{ else }}
			<input type="button" value="Show Tokens" onclick="window.location.href = '?tokens=true'" />
			{{ end }}

			{{ if .ShowTokens }}
				{{ range $i, $ing := .Ingesters }}
					<h2>Instance: {{ .ID }}</h2>
					<p>
						Tokens:<br />
						{{ range $token := .Tokens }}
							{{ $token }}
						{{ end }}
					</p>
				{{ end }}
			{{ end }}
		</form>
	</body>
</html>`

var pageTemplate *template.Template

func init() {
	t := template.New("webpage")
	t.Funcs(template.FuncMap{"mod": func(i, j int) bool { return i%j == 0 }})
	pageTemplate = template.Must(t.Parse(pageContent))
}

func (r *Ring) forget(ctx context.Context, id string) error {
	unregister := func(in interface{}) (out interface{}, retry bool, err error) {
		if in == nil {
			return nil, false, fmt.Errorf("found empty ring when trying to unregister")
		}

		ringDesc := in.(*Desc)
		ringDesc.RemoveIngester(id)
		return ringDesc, true, nil
	}
	return r.KVClient.CAS(ctx, r.key, unregister)
}

type ingesterDesc struct {
	ID                  string   `json:"id"`
	State               string   `json:"state"`
	Address             string   `json:"address"`
	HeartbeatTimestamp  string   `json:"timestamp"`
	RegisteredTimestamp string   `json:"registered_timestamp"`
	Zone                string   `json:"zone"`
	Tokens              []uint32 `json:"tokens"`
	NumTokens           int      `json:"-"`
	Ownership           float64  `json:"-"`
}

type httpResponse struct {
	Ingesters  []ingesterDesc `json:"shards"`
	Now        time.Time      `json:"now"`
	ShowTokens bool           `json:"-"`
}

func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		// Reject the destructive mutation unless the operator has explicitly
		// opted in by enabling the dangerous admin endpoints. Without this
		// gate any unauthenticated caller that can reach the Cortex HTTP
		// port could remove instances from the shared hash ring, breaking
		// writes/reads and risking data loss.
		if !DangerousAdminEndpointsEnabled() {
			level.Warn(r.logger).Log("msg", "rejecting ring forget request: dangerous admin endpoints are disabled")
			http.Error(w, "ring forget is disabled; enable dangerous admin endpoints to use this action", http.StatusForbidden)
			return
		}

		// Even when the endpoint is enabled, require a valid CSRF double-submit
		// token so a cross-origin form POST from a browser that can reach the
		// admin port cannot trigger the mutation on its own.
		if err := verifyCSRF(req); err != nil {
			level.Warn(r.logger).Log("msg", "rejecting ring forget request: CSRF validation failed", "err", err)
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}

		ingesterID := req.FormValue("forget")
		if ingesterID == "" {
			http.Error(w, "missing forget instance id", http.StatusBadRequest)
			return
		}
		if err := r.forget(req.Context(), ingesterID); err != nil {
			level.Error(r.logger).Log("msg", "error forgetting instance", "err", err)
		}

		// Implement PRG pattern to prevent double-POST and work with CSRF middleware.
		// https://en.wikipedia.org/wiki/Post/Redirect/Get

		// http.Redirect() would convert our relative URL to absolute, which is not what we want.
		// Browser knows how to do that, and it also knows real URL. Furthermore it will also preserve tokens parameter.
		// Note that relative Location URLs are explicitly allowed by specification, so we're not doing anything wrong here.
		w.Header().Set("Location", "#")
		w.WriteHeader(http.StatusFound)

		return
	}

	r.mtx.RLock()
	defer r.mtx.RUnlock()

	ingesterIDs := []string{}
	for id := range r.ringDesc.Ingesters {
		ingesterIDs = append(ingesterIDs, id)
	}
	sort.Strings(ingesterIDs)

	now := time.Now()
	var ingesters []ingesterDesc
	_, owned := r.countTokens()
	for _, id := range ingesterIDs {
		ing := r.ringDesc.Ingesters[id]
		heartbeatTimestamp := time.Unix(ing.Timestamp, 0)
		state := ing.State.String()
		if !r.IsHealthy(&ing, Reporting, now) {
			state = unhealthy
		}

		// Format the registered timestamp.
		registeredTimestamp := ""
		if ing.RegisteredTimestamp != 0 {
			registeredTimestamp = ing.GetRegisteredAt().String()
		}

		ingesters = append(ingesters, ingesterDesc{
			ID:                  id,
			State:               state,
			Address:             ing.Addr,
			HeartbeatTimestamp:  heartbeatTimestamp.String(),
			RegisteredTimestamp: registeredTimestamp,
			Tokens:              ing.Tokens,
			Zone:                ing.Zone,
			NumTokens:           len(ing.Tokens),
			Ownership:           (float64(owned[id]) / float64(math.MaxUint32)) * 100,
		})
	}

	tokensParam := req.URL.Query().Get("tokens")

	renderHTTPResponse(w, httpResponse{
		Ingesters:  ingesters,
		Now:        now,
		ShowTokens: tokensParam == "true",
	}, pageTemplate, req)
}

// RenderHTTPResponse either responds with json or a rendered html page using the passed in template
// by checking the Accepts header
func renderHTTPResponse(w http.ResponseWriter, v httpResponse, t *template.Template, r *http.Request) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		writeJSONResponse(w, v)
		return
	}

	// Mint a per-request CSRF token, pin it with a cookie and substitute it
	// for the placeholder emitted by the template so the Forget form posts a
	// token that matches the cookie.
	token, err := newCSRFToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfTokenCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})

	var buf strings.Builder
	if err := t.Execute(&buf, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered := strings.ReplaceAll(buf.String(), csrfTokenPlaceholder, template.HTMLEscapeString(token))
	_, _ = w.Write([]byte(rendered))
}

// WriteJSONResponse writes some JSON as a HTTP response.
func writeJSONResponse(w http.ResponseWriter, v httpResponse) {
	w.Header().Set("Content-Type", "application/json")

	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We ignore errors here, because we cannot do anything about them.
	// Write will trigger sending Status code, so we cannot send a different status code afterwards.
	// Also this isn't internal error, but error communicating with client.
	_, _ = w.Write(data)
}
