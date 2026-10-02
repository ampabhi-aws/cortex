package memberlist

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/hashicorp/memberlist"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/util/services"
)

// KVInitService initializes a memberlist.KV on first call to GetMemberlistKV, and starts it. On stop,
// KV is stopped too. If KV fails, error is reported from the service.
type KVInitService struct {
	services.Service

	// config used for initialization
	cfg         *KVConfig
	logger      log.Logger
	dnsProvider DNSProvider
	registerer  prometheus.Registerer

	// init function, to avoid multiple initializations.
	init sync.Once

	// state
	kv      atomic.Value
	err     error
	watcher *services.FailureWatcher
}

func NewKVInitService(cfg *KVConfig, logger log.Logger, dnsProvider DNSProvider, registerer prometheus.Registerer) *KVInitService {
	kvinit := &KVInitService{
		cfg:         cfg,
		watcher:     services.NewFailureWatcher(),
		logger:      logger,
		registerer:  registerer,
		dnsProvider: dnsProvider,
	}
	kvinit.Service = services.NewBasicService(nil, kvinit.running, kvinit.stopping).WithName("memberlist KV service")
	return kvinit
}

// GetMemberlistKV will initialize Memberlist.KV on first call, and add it to service failure watcher.
func (kvs *KVInitService) GetMemberlistKV() (*KV, error) {
	kvs.init.Do(func() {
		kv := NewKV(*kvs.cfg, kvs.logger, kvs.dnsProvider, kvs.registerer)
		kvs.watcher.WatchService(kv)
		kvs.err = kv.StartAsync(context.Background())

		kvs.kv.Store(kv)
	})

	return kvs.getKV(), kvs.err
}

// Returns KV if it was initialized, or nil.
func (kvs *KVInitService) getKV() *KV {
	kv := kvs.kv.Load()
	if kv == nil {
		return nil
	}
	return kv.(*KV)
}

func (kvs *KVInitService) running(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-kvs.watcher.Chan():
		// Only happens if KV service was actually initialized in GetMemberlistKV and it fails.
		return err
	}
}

func (kvs *KVInitService) stopping(_ error) error {
	kv := kvs.getKV()
	if kv == nil {
		return nil
	}

	return services.StopAndAwaitTerminated(context.Background(), kv)
}

func (kvs *KVInitService) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	kv := kvs.getKV()
	if kv == nil {
		w.Header().Set("Content-Type", "text/plain")
		// Ignore inactionable errors.
		_, _ = w.Write([]byte("This instance doesn't use memberlist."))
		return
	}

	const (
		downloadKeyParam    = "downloadKey"
		viewKeyParam        = "viewKey"
		viewMsgParam        = "viewMsg"
		deleteMessagesParam = "deleteMessages"
		verboseParam        = "verbose"
	)

	if err := req.ParseForm(); err == nil {
		// verbose=true opts in to disclosing per-instance addresses, tokens and raw
		// gossip values. The default view omits these so that a bare GET of the
		// memberlist page cannot be used as a reconnaissance oracle for ring
		// poisoning (CWE-1212 / CWE-552). The route itself is still subject to
		// the operator-network / reverse-proxy auth model documented in
		// docs/architecture.md.
		verbose := len(req.Form[verboseParam]) > 0 && req.Form[verboseParam][0] == "true"

		if req.Form[downloadKeyParam] != nil {
			if !verbose {
				http.Error(w, "raw key download requires ?verbose=true", http.StatusForbidden)
				return
			}
			downloadKey(w, kv, kv.storeCopy(), req.Form[downloadKeyParam][0]) // Use first value, ignore the rest.
			return
		}

		if req.Form[viewKeyParam] != nil {
			if !verbose {
				http.Error(w, "viewing decoded key values requires ?verbose=true", http.StatusForbidden)
				return
			}
			viewKey(w, kv.storeCopy(), req.Form[viewKeyParam][0], getFormat(req))
			return
		}

		if req.Form[viewMsgParam] != nil {
			if !verbose {
				http.Error(w, "viewing gossip messages requires ?verbose=true", http.StatusForbidden)
				return
			}
			msgID, err := strconv.Atoi(req.Form[viewMsgParam][0])
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			sent, received := kv.getSentAndReceivedMessages()

			for _, m := range append(sent, received...) {
				if m.ID == msgID {
					viewMessage(w, kv, m, getFormat(req))
					return
				}
			}

			http.Error(w, "message not found", http.StatusNotFound)
			return
		}

		if len(req.Form[deleteMessagesParam]) > 0 && req.Form[deleteMessagesParam][0] == "true" {
			// Clearing the gossip message history is a server-side state change and
			// must not be reachable from a GET (including cross-origin image/link
			// loads in an operator's browser). Require a non-GET method.
			if req.Method == http.MethodGet || req.Method == http.MethodHead {
				w.Header().Set("Allow", "POST")
				http.Error(w, "deleteMessages requires POST", http.StatusMethodNotAllowed)
				return
			}

			kv.deleteSentReceivedMessages()

			// Redirect back.
			w.Header().Set("Location", "?"+deleteMessagesParam+"=false")
			w.WriteHeader(http.StatusFound)
			return
		}
	}

	// Determine verbose mode for the index page too (ParseForm may have failed above,
	// in which case we conservatively default to non-verbose).
	verbose := len(req.Form["verbose"]) > 0 && req.Form["verbose"][0] == "true"

	members := kv.memberlist.Members()
	sort.Slice(members, func(i, j int) bool {
		return members[i].Name < members[j].Name
	})

	sent, received := kv.getSentAndReceivedMessages()

	sortedMembers := make([]memberInfo, 0, len(members))
	for _, m := range members {
		mi := memberInfo{Name: m.Name, State: m.State}
		if verbose {
			mi.Address = m.Address()
		}
		sortedMembers = append(sortedMembers, mi)
	}

	v := pageData{
		Now:              time.Now(),
		Memberlist:       kv.memberlist,
		SortedMembers:    sortedMembers,
		Store:            kv.storeCopy(),
		SentMessages:     sent,
		ReceivedMessages: received,
		Verbose:          verbose,
	}

	accept := req.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
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
		return
	}

	err := pageTemplate.Execute(w, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getFormat(req *http.Request) string {
	const viewFormat = "format"

	format := ""
	if len(req.Form[viewFormat]) > 0 {
		format = req.Form[viewFormat][0]
	}
	return format
}

func viewMessage(w http.ResponseWriter, kv *KV, msg message, format string) {
	c := kv.GetCodec(msg.Pair.Codec)
	if c == nil {
		http.Error(w, "codec not found", http.StatusNotFound)
		return
	}

	val, err := c.Decode(msg.Pair.Value)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode: %v", err), http.StatusInternalServerError)
		return
	}

	formatValue(w, val, format)
}

func viewKey(w http.ResponseWriter, store map[string]valueDesc, key string, format string) {
	if store[key].value == nil {
		http.Error(w, "value not found", http.StatusNotFound)
		return
	}

	formatValue(w, store[key].value, format)
}

func formatValue(w http.ResponseWriter, val interface{}, format string) {

	w.WriteHeader(200)
	w.Header().Add("content-type", "text/plain")

	switch format {
	case "json", "json-pretty":
		enc := json.NewEncoder(w)
		if format == "json-pretty" {
			enc.SetIndent("", "    ")
		}

		err := enc.Encode(val)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	default:
		_, _ = fmt.Fprintf(w, "%#v", val)
	}
}

func downloadKey(w http.ResponseWriter, kv *KV, store map[string]valueDesc, key string) {
	if store[key].value == nil {
		http.Error(w, "value not found", http.StatusNotFound)
		return
	}

	val := store[key]

	c := kv.GetCodec(store[key].codecID)
	if c == nil {
		http.Error(w, "codec not found", http.StatusNotFound)
		return
	}

	encoded, err := c.Encode(val.value)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Add("content-type", "application/octet-stream")
	// Set content-length so that client knows whether it has received full response or not.
	w.Header().Add("content-length", strconv.Itoa(len(encoded)))
	w.Header().Add("content-disposition", fmt.Sprintf("attachment; filename=%d-%s", val.version, key))
	w.WriteHeader(200)

	// Ignore errors, we cannot do anything about them.
	_, _ = w.Write(encoded)
}

type pageData struct {
	Now              time.Time
	Memberlist       *memberlist.Memberlist
	SortedMembers    []memberInfo
	Store            map[string]valueDesc
	SentMessages     []message
	ReceivedMessages []message
	Verbose          bool
}

// memberInfo is a redactable projection of memberlist.Node used by the status
// page. Address is only populated when the caller opts in to ?verbose=true, so
// a bare GET of /memberlist does not leak internal gRPC endpoints.
type memberInfo struct {
	Name    string
	Address string `json:"Address,omitempty"`
	State   memberlist.NodeStateType
}

var pageTemplate = template.Must(template.New("webpage").Funcs(template.FuncMap{
	"StringsJoin": strings.Join,
}).Parse(pageContent))

const pageContent = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Memberlist Status</title>
	</head>
	<body>
		<h1>Memberlist Status</h1>
		<p>Current time: {{ .Now }}</p>

		<ul>
		<li>Health Score: {{ .Memberlist.GetHealthScore }} (lower = better, 0 = healthy)</li>
		<li>Members: {{ .Memberlist.NumMembers }}</li>
		</ul>

		{{ if not .Verbose }}
		<p><em>Instance addresses, tokens and raw gossip values are hidden by default. Append <code>?verbose=true</code> to this URL to show them (operator-only).</em></p>
		{{ end }}

		<h2>KV Store</h2>

		<table width="100%" border="1">
			<thead>
				<tr>
					<th>Key</th>
					<th>Value Details</th>
					{{ if .Verbose }}<th>Actions</th>{{ end }}
				</tr>
			</thead>

			<tbody>
				{{ range $k, $v := .Store }}
				<tr>
					<td>{{ $k }}</td>
					<td>{{ $v }}</td>
					{{ if $.Verbose }}
					<td>
						<a href="?viewKey={{ $k }}&format=json&verbose=true">json</a>
						| <a href="?viewKey={{ $k }}&format=json-pretty&verbose=true">json-pretty</a>
						| <a href="?viewKey={{ $k }}&format=struct&verbose=true">struct</a>
						| <a href="?downloadKey={{ $k }}&verbose=true">download</a>
					</td>
					{{ end }}
				</tr>
				{{ end }}
			</tbody>
		</table>

		<p>Note that value "version" is node-specific. It starts with 0 (on restart), and increases on each received update. Size is in bytes.</p>

		<h2>Memberlist Cluster Members</h2>

		<table width="100%" border="1">
			<thead>
				<tr>
					<th>Name</th>
					{{ if .Verbose }}<th>Address</th>{{ end }}
					<th>State</th>
				</tr>
			</thead>

			<tbody>
				{{ range .SortedMembers }}
				<tr>
					<td>{{ .Name }}</td>
					{{ if $.Verbose }}<td>{{ .Address }}</td>{{ end }}
					<td>{{ .State }}</td>
				</tr>
				{{ end }}
			</tbody>
		</table>

		<p>State: 0 = Alive, 1 = Suspect, 2 = Dead, 3 = Left</p>

		<h2>Received Messages</h2>

		<form method="POST" action="?deleteMessages=true" style="display:inline">
			<button type="submit">Delete All Messages (received and sent)</button>
		</form>

		<table width="100%" border="1">
			<thead>
				<tr>
					<th>ID</th>
					<th>Time</th>
					<th>Key</th>
					<th>Value in the Message</th>
					<th>Version After Update (0 = no change)</th>
					<th>Changes</th>
					{{ if .Verbose }}<th>Actions</th>{{ end }}
				</tr>
			</thead>

			<tbody>
				{{ range .ReceivedMessages }}
				<tr>
					<td>{{ .ID }}</td>
					<td>{{ .Time.Format "15:04:05.000" }}</td>
					<td>{{ .Pair.Key }}</td>
					<td>size: {{ .Pair.Value | len }}, codec: {{ .Pair.Codec }}</td>
					<td>{{ .Version }}</td>
					<td>{{ StringsJoin .Changes ", " }}</td>
					{{ if $.Verbose }}
					<td>
						<a href="?viewMsg={{ .ID }}&format=json&verbose=true">json</a>
						| <a href="?viewMsg={{ .ID }}&format=json-pretty&verbose=true">json-pretty</a>
						| <a href="?viewMsg={{ .ID }}&format=struct&verbose=true">struct</a>
					</td>
					{{ end }}
				</tr>
				{{ end }}
			</tbody>
		</table>

		<h2>Sent Messages</h2>

		<form method="POST" action="?deleteMessages=true" style="display:inline">
			<button type="submit">Delete All Messages (received and sent)</button>
		</form>

		<table width="100%" border="1">
			<thead>
				<tr>
					<th>ID</th>
					<th>Time</th>
					<th>Key</th>
					<th>Value</th>
					<th>Version</th>
					<th>Changes</th>
					{{ if .Verbose }}<th>Actions</th>{{ end }}
				</tr>
			</thead>

			<tbody>
				{{ range .SentMessages }}
				<tr>
					<td>{{ .ID }}</td>
					<td>{{ .Time.Format "15:04:05.000" }}</td>
					<td>{{ .Pair.Key }}</td>
					<td>size: {{ .Pair.Value | len }}, codec: {{ .Pair.Codec }}</td>
					<td>{{ .Version }}</td>
					<td>{{ StringsJoin .Changes ", " }}</td>
					{{ if $.Verbose }}
					<td>
						<a href="?viewMsg={{ .ID }}&format=json&verbose=true">json</a>
						| <a href="?viewMsg={{ .ID }}&format=json-pretty&verbose=true">json-pretty</a>
						| <a href="?viewMsg={{ .ID }}&format=struct&verbose=true">struct</a>
					</td>
					{{ end }}
				</tr>
				{{ end }}
			</tbody>
		</table>
	</body>
</html>`
