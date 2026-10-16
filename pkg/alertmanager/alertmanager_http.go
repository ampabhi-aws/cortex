package alertmanager

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/hashicorp/memberlist"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/services"
)

// safePeerNameMaxLen is the maximum length of a gossip peer name displayed on
// the status page. memberlist does not impose a character-set or length limit
// on advertised node names, so we clamp them before rendering.
const safePeerNameMaxLen = 128

// sanitizePeerName returns name reduced to a conservative character set
// (letters, digits, '-', '_', '.', ':') and clamped to safePeerNameMaxLen.
// Disallowed bytes are replaced with '?'. This is defence in depth on top of
// html/template's contextual auto-escaping: it keeps the rendered page
// readable even if a peer advertises a name full of markup or control bytes.
func sanitizePeerName(name string) string {
	if len(name) > safePeerNameMaxLen {
		name = name[:safePeerNameMaxLen]
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.' || r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

var (
	ringStatusPageTemplate = template.Must(template.New("ringStatusPage").Parse(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Cortex Alertmanager Ring</title>
		</head>
		<body>
			<h1>Cortex Alertmanager Ring</h1>
			<p>{{ .Message }}</p>
		</body>
	</html>`))

	statusTemplate = template.Must(template.New("statusPage").Parse(`
    <!doctype html>
    <html>
        <head><title>Cortex Alertmanager Status</title></head>
        <body>
            <h1>Cortex Alertmanager Status</h1>
            {{ if not .ClusterInfo }}
                <p>Alertmanager gossip-based clustering is disabled.</p>
            {{ else }}
                <h2>Node</h2>
                <dl>
                    <dt>Name</dt><dd>{{.ClusterInfo.self.Name}}</dd>
                    <dt>Addr</dt><dd>{{.ClusterInfo.self.Addr}}</dd>
                    <dt>Port</dt><dd>{{.ClusterInfo.self.Port}}</dd>
                </dl>
                <h3>Members</h3>
                {{ with .ClusterInfo.members }}
                <table>
                    <tr><th>Name</th><th>Addr</th></tr>
                    {{ range . }}
                    <tr><td>{{ .Name }}</td><td>{{ .Addr }}</td></tr>
                    {{ end }}
                </table>
                {{ else }}
                <p>No peers</p>
                {{ end }}
            {{ end }}
        </body>
    </html>`))
)

// peerView is a rendering-only, template-safe projection of a memberlist node.
// We copy the fields the template reads and normalise Name through
// sanitizePeerName so untrusted gossip-advertised names cannot interfere with
// the rendered page even before html/template's contextual escaping.
type peerView struct {
	Name string
	Addr string
	Port uint16
}

func newPeerView(n *memberlist.Node) peerView {
	if n == nil {
		return peerView{}
	}
	addr := ""
	if n.Addr != nil {
		addr = n.Addr.String()
	}
	return peerView{
		Name: sanitizePeerName(n.Name),
		Addr: addr,
		Port: n.Port,
	}
}

// buildClusterInfo turns the raw map returned by Peer.Info() into the shape
// expected by statusTemplate, substituting sanitised peer names for the
// attacker-influenced memberlist values.
func buildClusterInfo(raw map[string]interface{}) map[string]interface{} {
	if raw == nil {
		return nil
	}
	out := map[string]interface{}{}
	if self, ok := raw["self"].(*memberlist.Node); ok {
		out["self"] = newPeerView(self)
	}
	if members, ok := raw["members"].([]*memberlist.Node); ok {
		views := make([]peerView, 0, len(members))
		for _, m := range members {
			views = append(views, newPeerView(m))
		}
		out["members"] = views
	}
	return out
}

func writeRingStatusMessage(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusOK)
	err := ringStatusPageTemplate.Execute(w, struct {
		Message string
	}{Message: message})
	if err != nil {
		level.Error(util_log.Logger).Log("msg", "unable to serve alertmanager ring page", "err", err)
	}
}

func (am *MultitenantAlertmanager) RingHandler(w http.ResponseWriter, req *http.Request) {
	if !am.cfg.ShardingEnabled {
		writeRingStatusMessage(w, "Alertmanager has no ring because sharding is disabled.")
		return
	}

	if am.State() != services.Running {
		// we cannot read the ring before the alertmanager is in Running state,
		// because that would lead to race condition.
		writeRingStatusMessage(w, "Alertmanager is not running yet.")
		return
	}

	am.ring.ServeHTTP(w, req)
}

// GetStatusHandler returns the status handler for this multi-tenant
// alertmanager.
func (am *MultitenantAlertmanager) GetStatusHandler() StatusHandler {
	return StatusHandler{
		am: am,
	}
}

// StatusHandler shows the status of the alertmanager.
type StatusHandler struct {
	am *MultitenantAlertmanager
}

// ServeHTTP serves the status of the alertmanager.
func (s StatusHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var clusterInfo map[string]interface{}
	if s.am.peer != nil {
		clusterInfo = buildClusterInfo(s.am.peer.Info())
	}
	err := statusTemplate.Execute(w, struct {
		ClusterInfo map[string]interface{}
	}{
		ClusterInfo: clusterInfo,
	})
	if err != nil {
		level.Error(util_log.Logger).Log("msg", "unable to serve alertmanager status page", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
