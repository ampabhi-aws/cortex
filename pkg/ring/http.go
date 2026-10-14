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
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/user"
)

// csrfTokenPlaceholder is the literal placeholder embedded in the ring status
// page template. ServeHTTP substitutes it with the process-level CSRF token
// before rendering, and validates it on POST requests that mutate the ring.
const csrfTokenPlaceholder = "$__CSRF_TOKEN_PLACEHOLDER__"

// csrfToken is a per-process random token used to defeat cross-site POSTs to
// the ring status pages. It is generated once at startup; callers must fetch
// the HTML form (which embeds the token) and echo it back in the `csrf_token`
// form field for forget requests to be accepted.
var csrfToken = func() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// Fall back to a time-based token; still unpredictable to an off-host
		// attacker and far better than the hard-coded placeholder.
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
		r.serveForget(w, req)
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

// serveForget authenticates, authorizes and audits a POST that unregisters a
// ring instance, then performs the forget. The route is expected to be
// registered with `auth=true` so that a tenant/operator identity has already
// been injected into the request context by the HTTP auth middleware (which
// rejects requests missing the identity header before this handler runs).
// On top of that this method enforces:
//   - a per-process CSRF token (the hidden `csrf_token` form field that the
//     page template emits);
//   - a non-empty `forget` instance ID that actually exists in the current
//     ring descriptor; and
//   - an audit-log line with the caller identity and source IP for every
//     attempt, successful or not.
func (r *Ring) serveForget(w http.ResponseWriter, req *http.Request) {
	caller, _ := user.ExtractOrgID(req.Context())
	src := clientIP(req)

	// Reject anonymous callers. When this handler is wired behind the HTTP
	// auth middleware the middleware itself returns 401 first; this is a
	// defence-in-depth check for deployments that register the route
	// directly, and it keeps the audit log honest.
	if caller == "" {
		level.Warn(r.logger).Log("msg", "rejected unauthenticated ring forget", "src", src, "path", req.URL.Path)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// Parse the form explicitly so that we can both validate CSRF and read
	// the target instance ID without relying on implicit parsing.
	if err := req.ParseForm(); err != nil {
		level.Warn(r.logger).Log("msg", "rejected malformed ring forget", "caller", caller, "src", src, "err", err)
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	token := req.PostForm.Get("csrf_token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(csrfToken)) != 1 {
		level.Warn(r.logger).Log("msg", "rejected ring forget: bad CSRF token", "caller", caller, "src", src, "path", req.URL.Path)
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	ingesterID := strings.TrimSpace(req.PostForm.Get("forget"))
	if ingesterID == "" {
		level.Warn(r.logger).Log("msg", "rejected ring forget: missing instance id", "caller", caller, "src", src)
		http.Error(w, "missing forget instance id", http.StatusBadRequest)
		return
	}

	r.mtx.RLock()
	exists := false
	if r.ringDesc != nil {
		_, exists = r.ringDesc.Ingesters[ingesterID]
	}
	r.mtx.RUnlock()
	if !exists {
		level.Warn(r.logger).Log("msg", "rejected ring forget: unknown instance", "caller", caller, "src", src, "instance", ingesterID)
		http.Error(w, "unknown instance", http.StatusNotFound)
		return
	}

	level.Info(r.logger).Log("msg", "ring forget requested", "caller", caller, "src", src, "instance", ingesterID, "path", req.URL.Path)
	if err := r.forget(req.Context(), ingesterID); err != nil {
		level.Error(r.logger).Log("msg", "error forgetting instance", "caller", caller, "src", src, "instance", ingesterID, "err", err)
		http.Error(w, "forget failed", http.StatusInternalServerError)
		return
	}
	level.Info(r.logger).Log("msg", "ring forget completed", "caller", caller, "src", src, "instance", ingesterID, "path", req.URL.Path)

	// Implement PRG pattern to prevent double-POST and work with CSRF middleware.
	// https://en.wikipedia.org/wiki/Post/Redirect/Get
	//
	// http.Redirect() would convert our relative URL to absolute, which is not what we want.
	// Browser knows how to do that, and it also knows real URL. Furthermore it will also preserve tokens parameter.
	// Note that relative Location URLs are explicitly allowed by specification, so we're not doing anything wrong here.
	w.Header().Set("Location", "#")
	w.WriteHeader(http.StatusFound)
}

// clientIP returns the best-effort client IP for audit logging. Any proxy
// header handling is deliberately left to upstream middleware (which is also
// how Cortex extracts the tenant); we only unwrap the RemoteAddr port.
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// RenderHTTPResponse either responds with json or a rendered html page using the passed in template
// by checking the Accepts header
func renderHTTPResponse(w http.ResponseWriter, v httpResponse, t *template.Template, r *http.Request) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		writeJSONResponse(w, v)
		return
	}

	var buf strings.Builder
	if err := t.Execute(&buf, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Substitute the CSRF token placeholder with the per-process token so that
	// legitimate operators submitting the embedded form echo it back on POST.
	body := strings.ReplaceAll(buf.String(), csrfTokenPlaceholder, csrfToken)
	_, _ = w.Write([]byte(body))
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
