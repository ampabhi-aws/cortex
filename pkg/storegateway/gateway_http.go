package storegateway

import (
	"net/http"
	"text/template"

	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/user"

	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/services"
)

// ringForgetCSRFHeader is a custom request header required for mutating
// requests to the store-gateway ring page. Browsers' simple cross-origin
// HTML form submissions cannot set custom request headers, so requiring
// its presence prevents CSRF-driven "forget" requests from being triggered
// by a victim operator's browser.
const ringForgetCSRFHeader = "X-Cortex-CSRF-Token"

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

	// The underlying ring.ServeHTTP exposes a mutating POST (?forget=<id>)
	// that removes an instance from the shared ring KV store. The route is
	// registered on an unauthenticated admin endpoint, so split the read
	// path from the write path here and require an authenticated principal
	// plus a CSRF-safe header for the mutating action. GET requests retain
	// their previous behavior.
	if req.Method == http.MethodPost {
		orgID, _, err := user.ExtractOrgIDFromHTTPRequest(req)
		if err != nil || orgID == "" {
			level.Warn(util_log.Logger).Log(
				"msg", "rejected unauthenticated store-gateway ring forget request",
				"remote", req.RemoteAddr,
				"forget", req.FormValue("forget"),
			)
			http.Error(w, "authentication required for store-gateway ring modifications", http.StatusUnauthorized)
			return
		}
		if req.Header.Get(ringForgetCSRFHeader) == "" {
			level.Warn(util_log.Logger).Log(
				"msg", "rejected store-gateway ring forget request missing CSRF header",
				"principal", orgID,
				"remote", req.RemoteAddr,
				"forget", req.FormValue("forget"),
				"required_header", ringForgetCSRFHeader,
			)
			http.Error(w, "missing "+ringForgetCSRFHeader+" header", http.StatusForbidden)
			return
		}
		level.Info(util_log.Logger).Log(
			"msg", "authenticated store-gateway ring forget",
			"principal", orgID,
			"remote", req.RemoteAddr,
			"forget", req.FormValue("forget"),
		)
	}

	c.ring.ServeHTTP(w, req)
}
