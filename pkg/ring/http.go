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
	"time"

	"github.com/go-kit/log/level"
)

// csrfCookieName is the name of the cookie used for the double-submit CSRF
// protection on ring status pages. The cookie is HttpOnly, SameSite=Strict,
// Path=/ and short-lived.
const csrfCookieName = "cortex_ring_csrf"

// csrfTokenPlaceholder is the sentinel string embedded in the ring status
// template. It is replaced per-request with the fresh CSRF token that is also
// set in csrfCookieName. Clients must echo this value in the csrf_token form
// field of any POST request.
const csrfTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

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
		{{ if .AllowForget }}
		<form action="" method="POST">
			<input type="hidden" name="csrf_token" value="$__CSRF_TOKEN_PLACEHOLDER__">
		{{ else }}
		<form action="" method="GET">
		{{ end }}
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
						<td>
							{{ if $.AllowForget }}
							<button name="forget" value="{{ .ID }}" type="submit"{{ if .Healthy }} disabled title="Instance is healthy; refuse to forget."{{ end }}>Forget</button>
							{{ else }}
							<em>disabled</em>
							{{ end }}
						</td>
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

// errForgetInstanceUnknown is returned when the forget target is empty or not
// in the current ring. In that case no KV write is performed.
var errForgetInstanceUnknown = fmt.Errorf("instance id is empty or not in the ring")

// errForgetInstanceHealthy is returned when the forget target is still
// heartbeating/healthy. Forgetting a healthy instance would simply be
// re-registered by its lifecycler and generates needless ring churn, so this
// is refused without touching the KV store.
var errForgetInstanceHealthy = fmt.Errorf("refusing to forget a healthy instance")

// forget removes an instance from the ring if, and only if, the instance id is
// non-empty, currently present in the ring, and not healthy. On any of those
// failing preconditions the CAS callback returns (nil, false, nil) so no write
// is performed against the KV store and no gossip broadcast is triggered.
func (r *Ring) forget(ctx context.Context, id string) error {
	if id == "" {
		return errForgetInstanceUnknown
	}

	// Snapshot the predicates against the Ring's in-memory view before we
	// enter the CAS loop. We re-check inside the callback against the
	// authoritative value coming back from the KV store, but this fast-path
	// avoids any KV traffic for obviously bad requests.
	if !r.HasInstance(id) {
		return errForgetInstanceUnknown
	}
	if r.isInstanceHealthy(id) {
		return errForgetInstanceHealthy
	}

	var refuseReason error
	unregister := func(in interface{}) (out interface{}, retry bool, err error) {
		if in == nil {
			return nil, false, fmt.Errorf("found empty ring when trying to unregister")
		}

		ringDesc := in.(*Desc)
		instance, ok := ringDesc.Ingesters[id]
		if !ok {
			// Nothing to do: unknown id. Return a nil descriptor so the KV
			// layer skips the write entirely.
			refuseReason = errForgetInstanceUnknown
			return nil, false, nil
		}
		if instance.IsHealthy(Reporting, r.cfg.HeartbeatTimeout, time.Now()) {
			refuseReason = errForgetInstanceHealthy
			return nil, false, nil
		}
		ringDesc.RemoveIngester(id)
		return ringDesc, true, nil
	}
	if err := r.KVClient.CAS(ctx, r.key, unregister); err != nil {
		return err
	}
	return refuseReason
}

// isInstanceHealthy returns true if the ring currently contains an instance
// matching id and that instance is healthy for the Reporting operation.
func (r *Ring) isInstanceHealthy(id string) bool {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	inst, ok := r.ringDesc.Ingesters[id]
	if !ok {
		return false
	}
	return inst.IsHealthy(Reporting, r.cfg.HeartbeatTimeout, time.Now())
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
	Healthy             bool     `json:"-"`
}

type httpResponse struct {
	Ingesters   []ingesterDesc `json:"shards"`
	Now         time.Time      `json:"now"`
	ShowTokens  bool           `json:"-"`
	AllowForget bool           `json:"-"`
}

// newCSRFToken returns a cryptographically random, URL-safe token.
func newCSRFToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-based pseudo-random value. We never return the
		// empty string because an empty token in the cookie would be matched
		// by an empty token in the form, which would defeat the check.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// setCSRFCookie writes the given token to the response as the double-submit
// cookie used to validate subsequent POSTs.
func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((15 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// verifyCSRF enforces the double-submit cookie pattern: the request must
// present a cookie and a csrf_token form value, both non-empty and equal in
// constant time. Any failure returns false and writes a 403 response.
func verifyCSRF(w http.ResponseWriter, req *http.Request) bool {
	cookie, err := req.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing CSRF cookie; load the status page first", http.StatusForbidden)
		return false
	}
	formToken := req.FormValue("csrf_token")
	if formToken == "" {
		http.Error(w, "missing csrf_token form value", http.StatusForbidden)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(formToken), []byte(cookie.Value)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		// Capability gating: the destructive POST handler is off by default.
		// Clusters that need the operator forget button must opt in via
		// -ring.allow-forget-via-http.
		if !r.cfg.AllowForgetViaHTTP {
			http.Error(w, "forget-via-HTTP is disabled; set -ring.allow-forget-via-http=true to enable", http.StatusNotFound)
			return
		}
		// CSRF protection: without a matching cookie + form field this POST
		// is rejected before touching the ring. The cookie is set on GET.
		if !verifyCSRF(w, req) {
			return
		}
		ingesterID := req.FormValue("forget")
		if err := r.forget(req.Context(), ingesterID); err != nil {
			switch err {
			case errForgetInstanceUnknown:
				level.Warn(r.logger).Log("msg", "refusing to forget unknown or empty instance id", "instance", ingesterID)
				http.Error(w, "unknown instance", http.StatusBadRequest)
				return
			case errForgetInstanceHealthy:
				level.Warn(r.logger).Log("msg", "refusing to forget healthy instance", "instance", ingesterID)
				http.Error(w, "refusing to forget a healthy instance", http.StatusConflict)
				return
			default:
				level.Error(r.logger).Log("msg", "error forgetting instance", "instance", ingesterID, "err", err)
				http.Error(w, "error forgetting instance", http.StatusInternalServerError)
				return
			}
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
		healthy := ing.IsHealthy(Reporting, r.cfg.HeartbeatTimeout, now)
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
			Healthy:             healthy,
		})
	}

	tokensParam := req.URL.Query().Get("tokens")

	// Issue a fresh CSRF token on every GET to the status page. The template
	// renderer substitutes it into the hidden form field and we store the
	// same value in a cookie for the double-submit check.
	var csrfToken string
	if r.cfg.AllowForgetViaHTTP {
		csrfToken = newCSRFToken()
		setCSRFCookie(w, csrfToken)
	}

	renderHTTPResponse(w, httpResponse{
		Ingesters:   ingesters,
		Now:         now,
		ShowTokens:  tokensParam == "true",
		AllowForget: r.cfg.AllowForgetViaHTTP,
	}, pageTemplate, req, csrfToken)
}

// RenderHTTPResponse either responds with json or a rendered html page using the passed in template
// by checking the Accepts header
func renderHTTPResponse(w http.ResponseWriter, v httpResponse, t *template.Template, r *http.Request, csrfToken string) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		writeJSONResponse(w, v)
		return
	}

	// Render the template into a buffer first so we can replace the CSRF
	// placeholder with the live token before writing the response.
	var sb strings.Builder
	if err := t.Execute(&sb, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page := sb.String()
	if v.AllowForget {
		page = strings.ReplaceAll(page, csrfTokenPlaceholder, template.HTMLEscapeString(csrfToken))
	} else {
		// When the forget capability is disabled no form token is emitted;
		// strip the placeholder so it never reaches a browser.
		page = strings.ReplaceAll(page, csrfTokenPlaceholder, "")
	}
	if _, err := w.Write([]byte(page)); err != nil {
		// Error communicating with client; nothing we can do.
		return
	}
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
