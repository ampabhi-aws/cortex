package ring

import (
	"context"
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
	// Harden admin pages against clickjacking / cross-origin framing.
	setAdminSecurityHeaders(w)

	if req.Method == http.MethodPost {
		// Reject cross-site POSTs to the destructive "forget" action.
		// This is a minimum origin-validation defence: in the absence of a real
		// per-session CSRF token, require that any state-changing request comes
		// from a same-origin context (or from a non-browser client that sends no
		// Origin/Sec-Fetch-Site headers at all).
		if !isSameOriginRequest(req) {
			http.Error(w, "cross-origin request blocked", http.StatusForbidden)
			return
		}

		ingesterID := req.FormValue("forget")
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
	}, pageTemplate, req)
}

// setAdminSecurityHeaders adds a conservative set of response headers to admin
// pages. These are defence-in-depth measures: they do not replace proper
// authentication, but they frustrate clickjacking and limit the damage from a
// stray reflected injection in these admin pages.
func setAdminSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "DENY")
	}
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
	}
}

// isSameOriginRequest returns true if the request can be safely treated as
// coming from a same-origin context. It uses the Fetch metadata header
// Sec-Fetch-Site when the client provides one (modern browsers always do), and
// falls back to a hostname comparison against the Origin / Referer headers.
// Non-browser clients that send none of these headers are allowed through so
// that automation and curl-based admin workflows continue to work.
func isSameOriginRequest(req *http.Request) bool {
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		// Browsers set this on every fetch. Only "same-origin" and "none"
		// (user-initiated top-level navigation) are safe for a state-changing
		// POST; "same-site", "cross-site" and anything unknown are rejected.
		if site != "same-origin" && site != "none" {
			return false
		}
	}

	if origin := req.Header.Get("Origin"); origin != "" && origin != "null" {
		if !originMatchesHost(origin, req.Host) {
			return false
		}
	}

	if referer := req.Header.Get("Referer"); referer != "" {
		if !originMatchesHost(referer, req.Host) {
			return false
		}
	}

	return true
}

// originMatchesHost returns true if the host component of rawURL matches
// requestHost. The scheme is intentionally not checked: an admin may legitimately
// front Cortex with a TLS-terminating proxy that forwards plaintext upstream.
func originMatchesHost(rawURL, requestHost string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, requestHost)
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
