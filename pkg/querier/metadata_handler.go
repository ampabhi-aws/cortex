package querier

import (
	"encoding/json"
	"net/http"
	"strconv"
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
//
// The handler mirrors the upstream Prometheus /api/v1/metadata handler and
// honours the `limit` and `metric` query parameters so a client can bound the
// response size. The JSON body is streamed with json.NewEncoder rather than
// being first marshalled into a single contiguous buffer, which avoids
// holding another full copy of the (potentially large) response in memory
// while it is being written to the client.
func MetadataHandler(d Distributor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the (optional) limit parameter. A value of -1 means
		// "no limit" and matches the upstream Prometheus semantics. An
		// omitted parameter is also treated as "no limit" to preserve
		// backwards compatibility with callers that previously received
		// the full response.
		limit := -1
		if s := r.FormValue("limit"); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(metadataResult{Status: statusError, Error: "limit must be a number"})
				return
			}
			limit = v
		}
		metricFilter := r.FormValue("metric")

		resp, err := d.MetricsMetadata(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(metadataResult{Status: statusError, Error: err.Error()})
			return
		}

		// Put all the elements of the pseudo-set into a map of slices for
		// marshalling, applying the optional `metric` filter and `limit`
		// early so we never materialise entries the client will not
		// receive.
		metrics := map[string][]metricMetadata{}
		for _, m := range resp {
			if metricFilter != "" && m.Metric != metricFilter {
				continue
			}

			ms, ok := metrics[m.Metric]
			if !ok {
				// A limit of -1 (or any other negative value) means
				// "no limit". Only count distinct metric families
				// against the limit, matching Prometheus semantics.
				if limit >= 0 && len(metrics) >= limit {
					break
				}
				// Most metrics will only hold 1 copy of the same metadata.
				ms = make([]metricMetadata, 0, 1)
			}
			metrics[m.Metric] = append(ms, metricMetadata{Type: string(m.Type), Help: m.Help, Unit: m.Unit})
		}

		// Stream the JSON so the whole document is never held in a
		// single contiguous buffer while being written to the client.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadataResult{Status: statusSuccess, Data: metrics})
	})
}
