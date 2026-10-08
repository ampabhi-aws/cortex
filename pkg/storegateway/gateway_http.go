package storegateway

import (
	"net/http"
	"text/template"

	"github.com/go-kit/log/level"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/services"
)

var (
	statusPageTemplate = template.Must(template.New("main").Parse(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Cortex Store Gateway Ring</title>
		</head>
		<body>
			<h1>Cortex Store Gateway Ring</h1>
			<p>{{ .Message }}</p>
		</body>
	</html>`))
)

func writeMessage(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusOK)
	err := statusPageTemplate.Execute(w, struct {
		Message string
	}{Message: message})

	if err != nil {
		level.Error(util_log.Logger).Log("msg", "unable to serve store gateway ring page", "err", err)
	}
}

func (c *StoreGateway) RingHandler(w http.ResponseWriter, req *http.Request) {
	if !c.gatewayCfg.ShardingEnabled {
		writeMessage(w, "Store gateway has no ring because sharding is disabled.")
		return
	}

	if c.State() != services.Running {
		// we cannot read the ring before the store gateway is in Running state,
		// because that would lead to race condition.
		writeMessage(w, "Store gateway is not running yet.")
		return
	}

	c.ring.ServeHTTP(w, req)
}

// RingForgetHandler is the authenticated admin endpoint that removes an
// instance from the store-gateway ring. It must be registered behind the API
// auth middleware.
func (c *StoreGateway) RingForgetHandler(w http.ResponseWriter, req *http.Request) {
	if !c.gatewayCfg.ShardingEnabled {
		http.Error(w, "store gateway ring is not enabled", http.StatusNotFound)
		return
	}

	if c.State() != services.Running {
		http.Error(w, "store gateway is not running yet", http.StatusServiceUnavailable)
		return
	}

	c.ring.ForgetHandler(w, req)
}
