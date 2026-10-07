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

	c.ring.ServeHTTP(w, req)
}

// ForgetHandler is the admin-only entry point used to "forget" a compactor
// from the ring. It is kept separate from RingHandler (status page) so that
// the mutating verb can be registered behind an authentication middleware.
func (c *Compactor) ForgetHandler(w http.ResponseWriter, req *http.Request) {
	if !c.compactorCfg.ShardingEnabled {
		http.Error(w, "compactor sharding is disabled", http.StatusBadRequest)
		return
	}
	if c.State() != services.Running {
		http.Error(w, "compactor is not running yet", http.StatusServiceUnavailable)
		return
	}
	c.ring.ServeForgetHTTP(w, req)
}
