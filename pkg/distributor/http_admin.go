package distributor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cortexproject/cortex/pkg/util"
)

const tpl = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Cortex Ingester Stats</title>
	</head>
	<body>
		<h1>Cortex Ingester Stats</h1>
		<p>Current time: {{ .Now }}</p>
		<p><b>NB stats do not account for replication factor, which is currently set to {{ .ReplicationFactor }}</b></p>
		<form action="" method="POST">
			<input type="hidden" name="csrf_token" value="$__CSRF_TOKEN_PLACEHOLDER__">
			<table border="1">
				<thead>
					<tr>
						<th>User</th>
						<th># Series</th>
						<th>Total Ingest Rate</th>
						<th>API Ingest Rate</th>
						<th>Rule Ingest Rate</th>
					</tr>
				</thead>
				<tbody>
					{{ range .Stats }}
					<tr>
						<td>{{ .UserID }}</td>
						<td align='right'>{{ .UserStats.NumSeries }}</td>
						<td align='right'>{{ printf "%.2f" .UserStats.IngestionRate }}</td>
						<td align='right'>{{ printf "%.2f" .UserStats.APIIngestionRate }}</td>
						<td align='right'>{{ printf "%.2f" .UserStats.RuleIngestionRate }}</td>
					</tr>
					{{ end }}
				</tbody>
			</table>
		</form>
	</body>
</html>`

var tmpl *template.Template

func init() {
	tmpl = template.Must(template.New("webpage").Parse(tpl))
}

type userStatsByTimeseries []UserIDStats

func (s userStatsByTimeseries) Len() int      { return len(s) }
func (s userStatsByTimeseries) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s userStatsByTimeseries) Less(i, j int) bool {
	return s[i].NumSeries > s[j].NumSeries ||
		(s[i].NumSeries == s[j].NumSeries && s[i].UserID < s[j].UserID)
}

// AllUserStatsHandler shows stats for all users.
func (d *Distributor) AllUserStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := d.AllUserStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sort.Sort(userStatsByTimeseries(stats))

	if encodings, found := r.Header["Accept"]; found &&
		len(encodings) > 0 && strings.Contains(encodings[0], "json") {
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			http.Error(w, fmt.Sprintf("Error marshalling response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	v := struct {
		Now               time.Time     `json:"now"`
		Stats             []UserIDStats `json:"stats"`
		ReplicationFactor int           `json:"replicationFactor"`
	}{
		Now:               time.Now(),
		Stats:             stats,
		ReplicationFactor: d.ingestersRing.ReplicationFactor(),
	}
	renderPage(w, r, v)
}

// renderPage mirrors util.RenderHTTPResponse but substitutes the CSRF
// token placeholder in the rendered HTML so admin forms carry a real token.
// This handler is GET-only, but keeping the hidden token here means that if a
// POST action is added in the future, CSRF validation can be enforced by
// calling util.CheckCSRF.
func renderPage(w http.ResponseWriter, r *http.Request, v interface{}) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		util.WriteJSONResponse(w, v)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	util.SetCSRFCookie(w)
	_, _ = w.Write(util.InjectCSRFToken(buf.Bytes()))
}
