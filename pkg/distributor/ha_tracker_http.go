package distributor

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/timestamp"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

const errNoOrgID = "no org id"

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

var trackerTmpl *template.Template

func init() {
	trackerTmpl = template.Must(template.New("ha-tracker").Parse(trackerTpl))
}

func (h *haTracker) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Scope the status page to the authenticated tenant resolved from the
	// request context so that one tenant cannot enumerate other tenants'
	// HA cluster / replica metadata. The route is registered with auth=true
	// so the tenant ID is populated by the auth middleware before we get here.
	logger := util_log.WithContext(req.Context(), h.logger)
	userID, err := tenant.TenantID(req.Context())
	if err != nil {
		level.Error(logger).Log("msg", errNoOrgID, "err", err.Error())
		http.Error(w, fmt.Sprintf("%s: %s", errNoOrgID, err.Error()), http.StatusUnauthorized)
		return
	}
	userPrefix := userID + "/"

	h.electedLock.RLock()
	type replica struct {
		UserID       string        `json:"userID"`
		Cluster      string        `json:"cluster"`
		Replica      string        `json:"replica"`
		ElectedAt    time.Time     `json:"electedAt"`
		UpdateTime   time.Duration `json:"updateDuration"`
		FailoverTime time.Duration `json:"failoverDuration"`
	}

	electedReplicas := []replica{}
	for key, desc := range h.elected {
		// Only expose entries that belong to the authenticated tenant.
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

	util.RenderHTTPResponse(w, struct {
		Elected []replica `json:"elected"`
		Now     time.Time `json:"now"`
	}{
		Elected: electedReplicas,
		Now:     time.Now(),
	}, trackerTmpl, req)
}
