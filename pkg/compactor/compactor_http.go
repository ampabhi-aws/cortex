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

	// The underlying ring HTTP handler treats any POST as an administrative
	// "forget" of a ring instance, which mutates shared KV state and can be
	// used to steer compactor ownership. This endpoint is registered with
	// auth=false (see pkg/api/api.go), so without an external operator
	// authentication layer we must not expose that mutating action here.
	// Reject any non-GET method and log the attempt for auditing. Operators
	// that need to forget a compactor instance should do so via a separate
	// authenticated admin endpoint or by using an external auth proxy.
	if req.Method != http.MethodGet {
		level.Warn(util_log.Logger).Log(
			"msg", "rejected non-GET request to compactor ring endpoint",
			"method", req.Method,
			"remote_addr", req.RemoteAddr,
			"forget", req.FormValue("forget"),
			"user_agent", req.UserAgent(),
		)
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.ring.ServeHTTP(w, req)
}
