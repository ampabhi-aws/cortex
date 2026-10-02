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

// errInstanceStillHealthy is returned by forget when the target instance's
// heartbeat is still fresh, meaning it is not actually gone and must not be
// evicted from the ring.
var errInstanceStillHealthy = fmt.Errorf("refusing to forget instance with a fresh heartbeat")

func (r *Ring) forget(ctx context.Context, id string) error {
	unregister := func(in interface{}) (out interface{}, retry bool, err error) {
		if in == nil {
			return nil, false, fmt.Errorf("found empty ring when trying to unregister")
		}

		ringDesc := in.(*Desc)

		// Defence-in-depth: refuse to forget an instance that is still heart-
		// beating. Such an instance is not actually gone and will immediately
		// re-register itself on its next heartbeat; evicting it only causes a
		// transient re-shuffle that can be abused to repeatedly drop replicas.
		if ing, ok := ringDesc.Ingesters[id]; ok {
			if ing.IsHeartbeatHealthy(r.cfg.HeartbeatTimeout, time.Now()) {
				return nil, false, errInstanceStillHealthy
			}
		}

		ringDesc.RemoveIngester(id)
		return ringDesc, true, nil
	}
	return r.KVClient.CAS(ctx, r.key, unregister)
}

// sameOriginRequest reports whether a mutating request appears to originate
// from the same host that is serving it, based on the Origin/Referer headers.
// This is a lightweight CSRF defence: it blocks the "any origin can POST a
// form" primitive without requiring external middleware. Requests that carry
// no Origin or Referer header are allowed through so that direct admin tools
// (curl, ops scripts) keep working; browsers always attach one of these
// headers to cross-origin form submissions.
func sameOriginRequest(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		origin = req.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, req.Host)
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
		// CSRF defence: reject POSTs whose Origin/Referer, when present, does
		// not match the request's own host. This blocks the trivial cross-
		// origin-form primitive without requiring a cookie or token flow.
		if !sameOriginRequest(req) {
			level.Warn(r.logger).Log(
				"msg", "refused ring forget POST from a cross-origin caller",
				"caller", req.RemoteAddr,
				"origin", req.Header.Get("Origin"),
				"referer", req.Header.Get("Referer"),
			)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ingesterID := strings.TrimSpace(req.FormValue("forget"))
		if ingesterID == "" {
			http.Error(w, "missing instance id", http.StatusBadRequest)
			return
		}

		// Audit every attempt — success and failure — so that the action is
		// detectable even when it is initiated via a legitimate admin reverse
		// proxy. Logging happens before the CAS so a crash mid-call is still
		// attributable to a caller.
		level.Warn(r.logger).Log(
			"msg", "ring forget requested",
			"instance", ingesterID,
			"caller", req.RemoteAddr,
		)

		if err := r.forget(req.Context(), ingesterID); err != nil {
			level.Error(r.logger).Log(
				"msg", "error forgetting instance",
				"instance", ingesterID,
				"caller", req.RemoteAddr,
				"err", err,
			)
			if err == errInstanceStillHealthy {
				http.Error(w, "refusing to forget instance with a fresh heartbeat", http.StatusConflict)
				return
			}
		} else {
			level.Warn(r.logger).Log(
				"msg", "forgot ring instance",
				"instance", ingesterID,
				"caller", req.RemoteAddr,
			)
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
