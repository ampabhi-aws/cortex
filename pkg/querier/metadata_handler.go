package querier

import (
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

type metricMetadata struct {
	Type string `json:"type"`
	Help string `json:"help"`
	Unit string `json:"unit"`
}

const (
	statusSuccess = "success"
	statusError   = "error"
)

type metadataResult struct {
	Status string                      `json:"status"`
	Data   map[string][]metricMetadata `json:"data,omitempty"`
	Error  string                      `json:"error,omitempty"`
}

// MetadataHandler returns metric metadata held by Cortex for a given tenant.
// It is kept and returned as a set.
func MetadataHandler(d Distributor) http.Handler {
	return MetadataHandlerWithLogger(util_log.Logger, d)
}

// MetadataHandlerWithLogger is like MetadataHandler but uses the provided logger
// to record internal errors server-side instead of leaking them to the caller.
func MetadataHandlerWithLogger(logger log.Logger, d Distributor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := d.MetricsMetadata(r.Context())
		if err != nil {
			// Log the raw error server-side; return a generic message to the caller
			// to avoid leaking internal identifiers.
			level.Warn(util_log.WithContext(r.Context(), logger)).Log("msg", "failed to retrieve metrics metadata", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			util.WriteJSONResponse(w, metadataResult{Status: statusError, Error: "internal server error retrieving metrics metadata"})
			return
		}

		// Put all the elements of the pseudo-set into a map of slices for marshalling.
		metrics := map[string][]metricMetadata{}
		for _, m := range resp {
			ms, ok := metrics[m.Metric]
			if !ok {
				// Most metrics will only hold 1 copy of the same metadata.
				ms = make([]metricMetadata, 0, 1)
				metrics[m.Metric] = ms
			}
			metrics[m.Metric] = append(ms, metricMetadata{Type: string(m.Type), Help: m.Help, Unit: m.Unit})
		}

		util.WriteJSONResponse(w, metadataResult{Status: statusSuccess, Data: metrics})
	})
}
