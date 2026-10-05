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
	if req.Method == http.MethodPost {
		// Reject cross-site / simple-form CSRF submissions before touching the KV store.
		// `forget` is a destructive, cluster-wide mutation: enforce (1) same-origin via
		// Origin/Referer matching the Host header, and (2) a non "simple" Content-Type
		// so an attacker page cannot submit this with a plain HTML <form>. The handler
		// is still intentionally unauthenticated — operators are expected to put auth
		// in front of Cortex — but the controls below close the CSRF path a browser
		// is willing to walk without the operator's intent.
		if err := checkSameOrigin(req); err != nil {
			level.Warn(r.logger).Log("msg", "rejected ring POST: cross-origin", "err", err, "remote", req.RemoteAddr)
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if ct := req.Header.Get("Content-Type"); !isAllowedForgetContentType(ct) {
			level.Warn(r.logger).Log("msg", "rejected ring POST: bad content-type", "content_type", ct, "remote", req.RemoteAddr)
			http.Error(w, "unsupported content-type for ring mutation", http.StatusUnsupportedMediaType)
			return
		}

		// Read `forget` from the request body only (PostFormValue), not from the URL
		// query string: a bodyless cross-site POST must not be able to carry the id.
		ingesterID := req.PostFormValue("forget")
		if ingesterID == "" {
			http.Error(w, "missing forget parameter", http.StatusBadRequest)
			return
		}
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

// isAllowedForgetContentType returns true if the request Content-Type is one
// a legitimate same-origin form submission from the ring status page would
// use. We accept application/x-www-form-urlencoded (what the embedded form
// posts) and multipart/form-data. We deliberately reject text/plain and the
// empty Content-Type, which are the two values a cross-site <form> or <a
// ping> is permitted to send without triggering a CORS preflight.
func isAllowedForgetContentType(ct string) bool {
	if ct == "" {
		return false
	}
	// Strip parameters (e.g. "; charset=UTF-8", "; boundary=...").
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.ToLower(strings.TrimSpace(ct)) {
	case "application/x-www-form-urlencoded", "multipart/form-data":
		return true
	}
	return false
}

// checkSameOrigin verifies the request's Origin (or, as a fallback, Referer)
// header host matches the request Host. Browsers always send Origin on POST
// requests to cross-origin targets, so a missing Origin with a matching
// Referer is treated as same-origin; a missing Origin AND missing Referer is
// rejected. Non-browser clients (curl, operational scripts) can set either
// header explicitly.
func checkSameOrigin(req *http.Request) error {
	host := req.Host
	if host == "" {
		return fmt.Errorf("missing Host header")
	}
	if origin := req.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("invalid Origin header: %w", err)
		}
		if !sameHost(u.Host, host) {
			return fmt.Errorf("Origin %q does not match Host %q", u.Host, host)
		}
		return nil
	}
	if referer := req.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err != nil {
			return fmt.Errorf("invalid Referer header: %w", err)
		}
		if !sameHost(u.Host, host) {
			return fmt.Errorf("Referer %q does not match Host %q", u.Host, host)
		}
		return nil
	}
	return fmt.Errorf("missing Origin and Referer headers")
}

// sameHost compares two host[:port] values for equality, tolerating a missing
// port on either side (e.g. "cortex.example" vs "cortex.example:80").
func sameHost(a, b string) bool {
	if a == b {
		return true
	}
	stripPort := func(h string) string {
		if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
			return h[:i]
		}
		return h
	}
	return stripPort(a) == stripPort(b)
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
