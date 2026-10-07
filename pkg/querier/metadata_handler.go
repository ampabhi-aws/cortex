package querier

import (
	"net/http"
	"strconv"

	"github.com/cortexproject/cortex/pkg/util"
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

// parseMetadataLimitParam parses an integer query parameter such as
// "limit" or "limit_per_metric". An empty string returns the provided
// default. Negative values mean unbounded, matching Prometheus semantics.
func parseMetadataLimitParam(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	return strconv.Atoi(s)
}

// MetadataHandler returns metric metadata held by Cortex for a given tenant.
// It is kept and returned as a set.
//
// The handler honours the Prometheus /api/v1/metadata query parameters:
//   - "limit":            maximum number of metric families to return (<0 = unbounded).
//   - "limit_per_metric": maximum number of metadata entries per metric family
//     (<0 = unbounded, 0 = suppress the metadata list entirely for a family).
//   - "metric":           restrict the response to a single metric family name.
//
// Honouring these parameters allows a client that asks for a bounded response
// to get one, and the handler stops aggregating once the cap is reached rather
// than materialising the entire per-tenant metadata set in memory.
func MetadataHandler(d Distributor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match Prometheus defaults: limit=-1 means no limit, so that this
		// handler stays wire-compatible with the vendored Prometheus handler.
		limit, err := parseMetadataLimitParam(r.FormValue("limit"), -1)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			util.WriteJSONResponse(w, metadataResult{Status: statusError, Error: "limit must be a number"})
			return
		}
		limitPerMetric, err := parseMetadataLimitParam(r.FormValue("limit_per_metric"), -1)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			util.WriteJSONResponse(w, metadataResult{Status: statusError, Error: "limit_per_metric must be a number"})
			return
		}
		metric := r.FormValue("metric")

		resp, err := d.MetricsMetadata(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			util.WriteJSONResponse(w, metadataResult{Status: statusError, Error: err.Error()})
			return
		}

		// Put all the elements of the pseudo-set into a map of slices for marshalling.
		metrics := map[string][]metricMetadata{}
		for _, m := range resp {
			// Optional metric-name filter: when set, drop everything that
			// does not match. This mirrors the Prometheus "metric" parameter.
			if metric != "" && m.Metric != metric {
				continue
			}

			ms, ok := metrics[m.Metric]
			// Stop aggregating once we have reached the requested number
			// of metric families. We check before inserting a new family so
			// that additional metadata entries for already-tracked families
			// are still folded in (matching the semantics of a set of
			// families).
			if !ok && limit >= 0 && len(metrics) >= limit {
				break
			}
			if !ok {
				// Most metrics will only hold 1 copy of the same metadata.
				ms = make([]metricMetadata, 0, 1)
				metrics[m.Metric] = ms
			}

			// Honour the per-metric cap: when non-negative, cap the
			// number of metadata entries kept per family. A negative
			// value means unbounded; zero means do not include any
			// metadata entries (same semantics as Prometheus).
			if limitPerMetric >= 0 && len(ms) >= limitPerMetric {
				continue
			}

			metrics[m.Metric] = append(ms, metricMetadata{Type: string(m.Type), Help: m.Help, Unit: m.Unit})
		}

		util.WriteJSONResponse(w, metadataResult{Status: statusSuccess, Data: metrics})
	})
}
