package ring

import (
	"encoding/json"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
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
	</body>
</html>`

var pageTemplate *template.Template

func init() {
	t := template.New("webpage")
	t.Funcs(template.FuncMap{"mod": func(i, j int) bool { return i%j == 0 }})
	pageTemplate = template.Must(t.Parse(pageContent))
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
	// Defence in depth: the mutating "forget" action over HTTP (previously
	// triggered by POST ?forget=<id>) has been removed because the ring HTTP
	// pages are registered on the tenant-facing listener with no authentication,
	// no authorization and no CSRF validation. Any non-GET method is now
	// rejected explicitly here, in addition to the router-level restriction in
	// pkg/api/api.go that no longer advertises POST on these routes.
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "ring mutation over HTTP is not supported; use an authenticated admin tool to remove instances", http.StatusMethodNotAllowed)
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
