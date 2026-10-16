package querier

import (
	"encoding/json"
	"errors"
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

	contentTypeJSON = "application/json"
)

type metadataResult struct {
	Status string                      `json:"status"`
	Data   map[string][]metricMetadata `json:"data,omitempty"`
	Error  string                      `json:"error,omitempty"`
}

var errInvalidMetadataLimit = errors.New("limit must be a non-negative integer")

// MetadataHandler returns metric metadata held by Cortex for a given tenant.
// It honours the ``limit`` and ``metric`` query parameters of the Prometheus
// /api/v1/metadata API; the per-tenant maximum metadata query cap is
// applied by the distributor. The successful response is streamed with a
// json.Encoder so the handler does not have to buffer the fully marshalled
// JSON output in memory before writing to the client.
func MetadataHandler(d Distributor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := parseMetadataRequest(r)
		if err != nil {
			writeMetadataError(w, http.StatusBadRequest, err.Error())
			return
		}

		resp, err := d.MetricsMetadata(r.Context(), req)
		if err != nil {
			// Return a generic error to the client; the internal error is
			// already available in the server logs.
			writeMetadataError(w, http.StatusBadRequest, "failed to fetch metric metadata")
			return
		}

		// Group the already-deduplicated and already-capped slice by metric
		// family name for the response. This is the only in-handler copy.
		metrics := make(map[string][]metricMetadata, len(resp))
		for _, m := range resp {
			metrics[m.Metric] = append(metrics[m.Metric], metricMetadata{
				Type: string(m.Type),
				Help: m.Help,
				Unit: m.Unit,
			})
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metadataResult{Status: statusSuccess, Data: metrics})
	})
}

// parseMetadataRequest extracts the ``limit`` and ``metric`` query
// parameters from the request. A missing ``limit`` is reported as -1 to
// signal "no caller-supplied limit".
func parseMetadataRequest(r *http.Request) (*MetricsMetadataRequest, error) {
	req := &MetricsMetadataRequest{
		Limit:  -1,
		Metric: r.FormValue("metric"),
	}
	if v := r.FormValue("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, errInvalidMetadataLimit
		}
		req.Limit = n
	}
	return req, nil
}

// writeMetadataError emits a JSON error payload. The Content-Type is set
// before WriteHeader so the response always carries the JSON media type
// (net/http silently drops header writes after WriteHeader has been
// called).
func writeMetadataError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(metadataResult{Status: statusError, Error: msg})
}
