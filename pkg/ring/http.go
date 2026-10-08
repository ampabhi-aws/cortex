package ring

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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

// Name of the cookie and form field used to carry the double-submit CSRF
// token on the ring status pages. The token is a fresh random value minted
// on every GET; the browser echoes it back as a hidden form input on the
// subsequent POST, and the handler requires the cookie and form values to
// match (constant-time). Cross-origin form submissions cannot read the
// cookie, so cannot forge a matching token.
const (
	csrfCookieName = "cortex_ring_csrf"
	csrfFormField  = "csrf_token"
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

// generateCSRFToken returns a cryptographically random, URL-safe token
// suitable for use as a double-submit CSRF value.
func generateCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// validateCSRF returns nil when the POST request carries a non-empty
// csrf_token form value AND a non-empty cortex_ring_csrf cookie AND they
// match in constant time. Any failure means the request is rejected.
func validateCSRF(req *http.Request) error {
	cookie, err := req.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return fmt.Errorf("missing csrf cookie")
	}
	form := req.FormValue(csrfFormField)
	if form == "" {
		return fmt.Errorf("missing csrf token")
	}
	if subtle.ConstantTimeCompare([]byte(form), []byte(cookie.Value)) != 1 {
		return fmt.Errorf("csrf token mismatch")
	}
	return nil
}

// sameOriginRequest returns true when a state-changing request appears to
// originate from the same site that served the page. Browser-originated CSRF
// attacks always carry a cross-origin Origin or Referer header on POST.
func sameOriginRequest(req *http.Request) bool {
	if fs := req.Header.Get("Sec-Fetch-Site"); fs != "" {
		return fs == "same-origin" || fs == "same-site" || fs == "none"
	}
	host := req.Host
	check := func(raw string) bool {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false
		}
		return strings.EqualFold(u.Host, host)
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		return check(origin)
	}
	if ref := req.Header.Get("Referer"); ref != "" {
		return check(ref)
	}
	// No browser-origin signal at all: a cross-site browser POST always
	// has at least Origin or Referer, so this is a non-browser caller
	// (curl, operator script). Those are already gated by the admin
	// authenticator at the route layer; allow the request to proceed.
	return true
}

func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		// Defense-in-depth: route registration already gates POST
		// behind the operator-configured admin authenticator, but the
		// ring handler itself must also fail closed in case this
		// handler is wired into another mux (direct ServeHTTP use,
		// embedded in RingHandler of other components, etc.).
		if !sameOriginRequest(req) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if err := validateCSRF(req); err != nil {
			level.Warn(r.logger).Log("msg", "rejecting ring POST: csrf validation failed", "err", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ingesterID := req.FormValue("forget")
		if err := r.forget(req.Context(), ingesterID); err != nil {
			level.Error(r.logger).Log("msg", "error forgetting instance", "err", err)
		}

		// PRG pattern: a relative Location keeps the browser on the
		// same URL and preserves the tokens parameter.
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

	// Mint a fresh CSRF token for this view, and set it as an
	// HttpOnly, SameSite=Strict cookie so a cross-origin page cannot
	// read it. The template echoes the same value into a hidden form
	// field; on POST the handler enforces that the two match.
	csrf := ""
	if token, err := generateCSRFToken(); err == nil {
		csrf = token
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   req.TLS != nil,
		})
	} else {
		level.Error(r.logger).Log("msg", "failed to generate csrf token", "err", err)
	}

	renderHTTPResponse(w, httpResponse{
		Ingesters:  ingesters,
		Now:        now,
		ShowTokens: tokensParam == "true",
		CSRFToken:  csrf,
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
