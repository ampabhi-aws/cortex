package distributor

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/timestamp"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
)

const trackerTpl = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Cortex HA Tracker Status</title>
	</head>
	<body>
		<h1>Cortex HA Tracker Status</h1>
		<p>Current time: {{ .Now }}</p>
		<table width="100%" border="1">
			<thead>
				<tr>
					<th>User ID</th>
					<th>Cluster</th>
					<th>Replica</th>
					<th>Elected Time</th>
					<th>Time Until Update</th>
					<th>Time Until Failover</th>
				</tr>
			</thead>
			<tbody>
				{{ range .Elected }}
				<tr>
					<td>{{ .UserID }}</td>
					<td>{{ .Cluster }}</td>
					<td>{{ .Replica }}</td>
					<td>{{ .ElectedAt }}</td>
					<td>{{ .UpdateTime }}</td>
					<td>{{ .FailoverTime }}</td>
				</tr>
				{{ end }}
			</tbody>
		</table>
	</body>
</html>`

// haTrackerPageDefaultLimit bounds how many elected entries ServeHTTP returns
// per request so a single caller cannot force an unbounded scan of the elected
// map while holding the read lock that checkReplica needs on the push path.
const haTrackerPageDefaultLimit = 1000

var trackerTmpl *template.Template

func init() {
	trackerTmpl = template.Must(template.New("ha-tracker").Parse(trackerTpl))
}

func (h *haTracker) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Require a tenant from the request context. The HA tracker keys are
	// cluster-wide (one entry per (tenant, cluster) pair), so without a
	// tenant scope the handler would disclose every tenant's HA cluster
	// and replica names to the caller.
	userID, err := tenant.TenantID(req.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Bound the amount of work performed per request so a caller cannot
	// force an O(n log n) scan over the whole elected map while holding
	// electedLock.
	limit := haTrackerPageDefaultLimit
	if raw := req.URL.Query().Get("limit"); raw != "" {
		if parsed, perr := strconv.Atoi(raw); perr == nil && parsed > 0 && parsed <= haTrackerPageDefaultLimit {
			limit = parsed
		}
	}

	type replica struct {
		UserID       string        `json:"userID"`
		Cluster      string        `json:"cluster"`
		Replica      string        `json:"replica"`
		ElectedAt    time.Time     `json:"electedAt"`
		UpdateTime   time.Duration `json:"updateDuration"`
		FailoverTime time.Duration `json:"failoverDuration"`
	}

	// The elected map is keyed by "<userID>/<cluster>". Only emit entries
	// whose key prefix matches the caller's tenant so the handler cannot
	// be used to enumerate other tenants' HA cluster/replica metadata.
	userPrefix := userID + "/"

	electedReplicas := []replica{}
	h.electedLock.RLock()
	for key, desc := range h.elected {
		if !strings.HasPrefix(key, userPrefix) {
			continue
		}
		chunks := strings.SplitN(key, "/", 2)
		if len(chunks) != 2 || chunks[0] != userID {
			continue
		}

		electedReplicas = append(electedReplicas, replica{
			UserID:       chunks[0],
			Cluster:      chunks[1],
			Replica:      desc.Replica,
			ElectedAt:    timestamp.Time(desc.ReceivedAt),
			UpdateTime:   time.Until(timestamp.Time(desc.ReceivedAt).Add(h.cfg.UpdateTimeout)),
			FailoverTime: time.Until(timestamp.Time(desc.ReceivedAt).Add(h.cfg.FailoverTimeout)),
		})
	}
	h.electedLock.RUnlock()

	sort.Slice(electedReplicas, func(i, j int) bool {
		first := electedReplicas[i]
		second := electedReplicas[j]

		if first.UserID != second.UserID {
			return first.UserID < second.UserID
		}
		return first.Cluster < second.Cluster
	})

	if len(electedReplicas) > limit {
		electedReplicas = electedReplicas[:limit]
	}

	util.RenderHTTPResponse(w, struct {
		Elected []replica `json:"elected"`
		Now     time.Time `json:"now"`
	}{
		Elected: electedReplicas,
		Now:     time.Now(),
	}, trackerTmpl, req)
}
