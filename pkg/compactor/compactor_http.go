package compactor

import (
	"html/template"
	"net/http"

	"github.com/go-kit/log/level"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/services"
)

var (
	compactorStatusPageTemplate = template.Must(template.New("main").Parse(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Cortex Compactor Ring</title>
		</head>
		<body>
			<h1>Cortex Compactor Ring</h1>
			<p>{{ .Message }}</p>
		</body>
	</html>`))
)

func writeMessage(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusOK)
	err := compactorStatusPageTemplate.Execute(w, struct {
		Message string
	}{Message: message})

	if err != nil {
		level.Error(util_log.Logger).Log("msg", "unable to serve compactor ring page", "err", err)
	}
}

func (c *Compactor) RingHandler(w http.ResponseWriter, req *http.Request) {
	if !c.compactorCfg.ShardingEnabled {
		writeMessage(w, "Compactor has no ring because sharding is disabled.")
		return
	}

	if c.State() != services.Running {
		// we cannot read the ring before Compactor is in Running state,
		// because that would lead to race condition.
		writeMessage(w, "Compactor is not running yet.")
		return
	}

	// Only GET (read status) and POST (forget action) are supported. Reject any
	// other method up-front so state-changing semantics cannot be smuggled in via
	// e.g. PUT/DELETE/PATCH. The route is registered for GET+POST only, but we
	// defend in depth here because this handler may be reached through other
	// routers (tests, embedding) as well.
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For the state-changing 'forget' action, validate the submitted instance ID
	// against current ring membership before forwarding to the ring HTTP handler.
	// This prevents attacker-controlled form data from triggering a KV CAS with
	// an arbitrary ID, and ensures we only ever attempt to remove instances that
	// are actually registered in the compactor ring.
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if ingesterID := req.FormValue("forget"); ingesterID != "" {
			if !c.ring.HasInstance(ingesterID) {
				level.Warn(util_log.Logger).Log("msg", "rejected compactor ring forget request for unknown instance", "instance", ingesterID)
				http.Error(w, "unknown instance", http.StatusBadRequest)
				return
			}
		}
	}

	c.ring.ServeHTTP(w, req)
}
