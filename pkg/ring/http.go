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

// csrfCookieName is the name of the cookie used to implement the
// double-submit cookie CSRF protection for the ring admin page.
const csrfCookieName = "cortex_ring_csrf"

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

// generateCSRFToken returns a cryptographically random, hex-encoded token
// suitable for use as a CSRF double-submit value.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// isValidCSRFToken returns true if s looks like a token issued by
// generateCSRFToken (64 lowercase hex characters). This guards against
// an attacker injecting an arbitrary cookie value that would then be
// trivially replayed in the form field.
func isValidCSRFToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ensureCSRFCookie returns the CSRF token bound to the caller via a cookie,
// generating and setting one if the request does not already carry a valid
// token cookie. The returned token is also the value that must be echoed
// back in the csrf_token form field on subsequent POSTs.
func ensureCSRFCookie(w http.ResponseWriter, req *http.Request) (string, error) {
	if c, err := req.Cookie(csrfCookieName); err == nil && isValidCSRFToken(c.Value) {
		return c.Value, nil
	}
	tok, err := generateCSRFToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   req.TLS != nil,
	})
	return tok, nil
}

// verifyCSRF performs double-submit cookie CSRF validation on the request.
// It requires that the csrf_token form value be a non-empty, well-formed
// token that matches the value of the csrfCookieName cookie in constant
// time. Any mismatch is treated as a CSRF failure.
func verifyCSRF(req *http.Request) error {
	formTok := req.FormValue("csrf_token")
	if !isValidCSRFToken(formTok) {
		return fmt.Errorf("missing or malformed csrf_token form value")
	}
	cookie, err := req.Cookie(csrfCookieName)
	if err != nil || !isValidCSRFToken(cookie.Value) {
		return fmt.Errorf("missing or malformed csrf cookie")
	}
	if subtle.ConstantTimeCompare([]byte(formTok), []byte(cookie.Value)) != 1 {
		return fmt.Errorf("csrf token mismatch")
	}
	return nil
}

// hasInstance reports whether the given instance ID is currently registered
// in the ring descriptor.
func (r *Ring) hasInstance(id string) bool {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if r.ringDesc == nil {
		return false
	}
	_, ok := r.ringDesc.Ingesters[id]
	return ok
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

func (r *Ring) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		// CSRF protection: the ring routes are mounted without authentication
		// (see pkg/api/api.go), so any client - including a cross-site form
		// in an operator's browser - can reach this handler. Implement the
		// double-submit cookie pattern: a random token is set as an HttpOnly,
		// SameSite=Strict cookie on GET and we require that the POST body
		// carry the same token in the csrf_token form field.
		if err := verifyCSRF(req); err != nil {
			level.Warn(r.logger).Log(
				"msg", "rejected ring forget request: CSRF validation failed",
				"err", err,
				"remote", req.RemoteAddr,
				"user_agent", req.UserAgent(),
			)
			http.Error(w, "forbidden: CSRF validation failed", http.StatusForbidden)
			return
		}

		ingesterID := req.FormValue("forget")
		if ingesterID == "" {
			http.Error(w, "missing forget instance ID", http.StatusBadRequest)
			return
		}
		if !r.hasInstance(ingesterID) {
			level.Warn(r.logger).Log(
				"msg", "rejected ring forget request: unknown instance",
				"instance", ingesterID,
				"remote", req.RemoteAddr,
				"user_agent", req.UserAgent(),
			)
			http.Error(w, "unknown instance", http.StatusNotFound)
			return
		}

		level.Info(r.logger).Log(
			"msg", "forgetting ring instance",
			"instance", ingesterID,
			"remote", req.RemoteAddr,
			"user_agent", req.UserAgent(),
		)
		if err := r.forget(req.Context(), ingesterID); err != nil {
			level.Error(r.logger).Log("msg", "error forgetting instance", "err", err, "instance", ingesterID)
			http.Error(w, "failed to forget instance", http.StatusInternalServerError)
			return
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

	// Issue (or re-use) the CSRF cookie so the rendered form carries a
	// token that is bound to this caller.
	csrfToken, err := ensureCSRFCookie(w, req)
	if err != nil {
		level.Error(r.logger).Log("msg", "failed to issue CSRF cookie", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
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
