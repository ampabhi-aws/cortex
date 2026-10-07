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
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log/level"
)

// csrfToken is a per-process random token embedded into the ring status
// page and required on every state-mutating POST. It is not a replacement
// for the external authentication/authorisation layer Cortex requires, but
// it defeats cross-site request forgery from an operator's browser that
// has been navigated to an attacker-controlled page: the attacker cannot
// read the token (same-origin policy), so cannot forge a valid POST, and
// requests with a mismatched or missing Origin/Referer are rejected before
// any ring mutation occurs. See pkg/ring/http.go ServeHTTP.
var csrfToken = func() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// Fall back to a time-based token; rand.Read on supported platforms
		// never actually returns an error, but we still want to boot.
		return fmt.Sprintf("ring-csrf-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}()

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
			<input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
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
	CSRFToken  string         `json:"-"`
}

// validCSRFToken returns true if the request body carries the per-process
// CSRF token in the `csrf_token` form field.
func validCSRFToken(req *http.Request) bool {
	got := req.FormValue("csrf_token")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(csrfToken)) == 1
}

// sameOriginRequest validates that a state-changing POST either carries an
// Origin/Referer whose host matches the request's Host header, or (when the
// browser attaches it) a `Sec-Fetch-Site` of same-origin/same-site/none. A
// request without any Origin or Referer header is rejected because browsers
// always attach at least one on cross-origin form submissions; server-side
// or curl clients that intentionally mutate the ring are expected to supply
// a matching Origin header along with the CSRF token embedded in the page.
func sameOriginRequest(req *http.Request) bool {
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		switch site {
		case "same-origin", "same-site", "none":
			// Explicit browser signal that this is not a cross-site POST.
		default:
			return false
		}
	}

	checkHost := func(raw string) (bool, bool) {
		if raw == "" {
			return false, false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false, false
		}
		return true, strings.EqualFold(u.Host, req.Host)
	}

	if present, ok := checkHost(req.Header.Get("Origin")); present {
		return ok
	}
	if present, ok := checkHost(req.Header.Get("Referer")); present {
		return ok
	}
	// No Origin and no Referer: refuse. Legitimate browser POSTs from the
	// embedded form always include at least Referer; scripted callers can
	// easily set Origin to match Host when they also provide the CSRF token.
	return false
}

func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		// Guard the state-mutating ring forget operation. Cortex delegates
		// authentication/authorisation to an external layer, but we still
		// have to defeat CSRF from an operator's browser landing on an
		// attacker page: without a valid same-origin request carrying the
		// per-process CSRF token embedded in the page, refuse to mutate
		// the shared ring KV. See https://en.wikipedia.org/wiki/Cross-site_request_forgery.
		if !sameOriginRequest(req) || !validCSRFToken(req) {
			level.Warn(r.logger).Log(
				"msg", "rejected ring forget POST: CSRF or same-origin check failed",
				"remote", req.RemoteAddr,
				"origin", req.Header.Get("Origin"),
				"referer", req.Header.Get("Referer"),
			)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ingesterID := req.FormValue("forget")
		if ingesterID == "" {
			http.Error(w, "missing forget parameter", http.StatusBadRequest)
			return
		}

		// Reject unknown instance IDs so that cross-site POSTs cannot be
		// used to probe for the presence of a ring member and so that we
		// surface typos to the operator rather than silently no-op.
		r.mtx.RLock()
		_, known := r.ringDesc.Ingesters[ingesterID]
		r.mtx.RUnlock()
		if !known {
			http.Error(w, "unknown instance", http.StatusBadRequest)
			return
		}

		level.Info(r.logger).Log(
			"msg", "ring forget POST accepted",
			"instance", ingesterID,
			"remote", req.RemoteAddr,
		)
		if err := r.forget(req.Context(), ingesterID); err != nil {
			level.Error(r.logger).Log("msg", "error forgetting instance", "err", err)
		}

		// Implement PRG pattern to prevent double-POST.
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
		CSRFToken:  csrfToken,
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

	err := t.Execute(w, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
