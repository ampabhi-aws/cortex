package ring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/user"
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
		{{ if .ForgetEnabled }}
		<form action="{{ .ForgetPath }}" method="POST">
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
							{{ if $.ForgetEnabled }}
							<button name="forget" value="{{ .ID }}" type="submit">Forget</button>
							{{ else }}
							&mdash;
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

// ErrForgetEndpointDisabled is returned when the operator POSTs to the forget
// endpoint but has not opted in via -ring.enable-forget-endpoint.
var ErrForgetEndpointDisabled = errors.New("ring forget endpoint is disabled; set -ring.enable-forget-endpoint to enable it")

// ErrMissingInstanceID is returned when the forget endpoint is called without
// an instance id. The handler refuses to issue a KV write for this case so a
// bogus POST cannot force unnecessary ring descriptor rewrites.
var ErrMissingInstanceID = errors.New("missing instance id")

func (r *Ring) forget(ctx context.Context, id string) error {
	if id == "" {
		return ErrMissingInstanceID
	}
	unregister := func(in interface{}) (out interface{}, retry bool, err error) {
		if in == nil {
			return nil, false, fmt.Errorf("found empty ring when trying to unregister")
		}

		ringDesc := in.(*Desc)
		// No-op for unknown instance ids so a bogus POST cannot force a KV write
		// (and the associated gossip broadcast on memberlist) for an id that is
		// not actually in the ring.
		if _, ok := ringDesc.Ingesters[id]; !ok {
			return nil, false, nil
		}
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
	Ingesters     []ingesterDesc `json:"shards"`
	Now           time.Time      `json:"now"`
	ShowTokens    bool           `json:"-"`
	ForgetEnabled bool           `json:"-"`
	ForgetPath    string         `json:"-"`
}

// ServeHTTP renders the read-only ring status page. The destructive "forget"
// operation lives behind a dedicated authenticated handler (ForgetHandler) so
// that a POST to the public status page can never mutate the shared KV ring.
func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		// Any non-GET request on the status page is refused. The forget
		// operation is served by ForgetHandler on a different route, behind
		// the API auth middleware and gated by -ring.enable-forget-endpoint.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	// Resolve the forget URL relative to the current page so operator-authored
	// proxies at arbitrary path prefixes continue to work.
	forgetPath := strings.TrimRight(req.URL.Path, "/") + "/forget"

	renderHTTPResponse(w, httpResponse{
		Ingesters:     ingesters,
		Now:           now,
		ShowTokens:    tokensParam == "true",
		ForgetEnabled: r.cfg.EnableForgetEndpoint,
		ForgetPath:    forgetPath,
	}, pageTemplate, req)
}

// ForgetHandler is the authenticated POST handler that removes an instance
// from the ring. It MUST be registered behind the API auth middleware so that
// an identity is always present before a destructive KV write is issued. It
// also requires the operator to have opted in via -ring.enable-forget-endpoint
// (default off).
func (r *Ring) ForgetHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Explicit opt-in: the destructive endpoint is disabled unless the operator
	// has set -ring.enable-forget-endpoint.
	if !r.cfg.EnableForgetEndpoint {
		level.Warn(r.logger).Log("msg", "refusing ring forget request: endpoint is disabled", "err", ErrForgetEndpointDisabled)
		http.Error(w, ErrForgetEndpointDisabled.Error(), http.StatusForbidden)
		return
	}

	ingesterID := req.FormValue("forget")
	if ingesterID == "" {
		http.Error(w, ErrMissingInstanceID.Error(), http.StatusBadRequest)
		return
	}

	// Identify the authenticated principal (as surfaced by the API auth
	// middleware via the X-Scope-OrgID header) so every successful mutation
	// is attributable in the audit log.
	principal, _ := user.ExtractOrgID(req.Context())
	if principal == "" {
		principal = "<unknown>"
	}

	if err := r.forget(req.Context(), ingesterID); err != nil {
		level.Error(r.logger).Log("msg", "error forgetting instance", "err", err, "principal", principal, "instance", ingesterID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	level.Info(r.logger).Log("msg", "ring forget", "principal", principal, "instance", ingesterID)

	// Implement PRG pattern to prevent double-POST and work with CSRF middleware.
	// https://en.wikipedia.org/wiki/Post/Redirect/Get
	//
	// Redirect back to the parent status page (strip the trailing "/forget").
	parent := strings.TrimSuffix(req.URL.Path, "/forget")
	if parent == "" {
		parent = "#"
	}
	w.Header().Set("Location", parent)
	w.WriteHeader(http.StatusFound)
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
