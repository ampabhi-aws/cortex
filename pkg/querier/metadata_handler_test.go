package querier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/prometheus/scrape"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMetadataHandler_Success(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return(
		[]scrape.MetricMetadata{
			{Metric: "alertmanager_dispatcher_aggregation_groups", Help: "Number of active aggregation groups", Type: "gauge", Unit: ""},
		},
		nil)

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	expectedJSON := `
	{
		"status": "success",
		"data": {
			"alertmanager_dispatcher_aggregation_groups": [
				{
					"help": "Number of active aggregation groups",
					"type": "gauge",
					"unit": ""
				}
			]
		}
	}
	`

	require.JSONEq(t, expectedJSON, string(responseBody))
}

func TestMetadataHandler_Limit(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return(
		[]scrape.MetricMetadata{
			{Metric: "metric_a", Help: "h_a", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "h_b", Type: "gauge", Unit: ""},
			{Metric: "metric_c", Help: "h_c", Type: "gauge", Unit: ""},
		},
		nil)

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?limit=1", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	// With limit=1 we must only get one metric family entry.
	parsed := metadataResult{}
	require.NoError(t, json.Unmarshal(responseBody, &parsed))
	require.Equal(t, statusSuccess, parsed.Status)
	require.Len(t, parsed.Data, 1)
}

func TestMetadataHandler_MetricFilter(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return(
		[]scrape.MetricMetadata{
			{Metric: "metric_a", Help: "h_a", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "h_b", Type: "gauge", Unit: ""},
		},
		nil)

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?metric=metric_b", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	parsed := metadataResult{}
	require.NoError(t, json.Unmarshal(responseBody, &parsed))
	require.Equal(t, statusSuccess, parsed.Status)
	require.Len(t, parsed.Data, 1)
	_, ok := parsed.Data["metric_b"]
	require.True(t, ok)
}

func TestMetadataHandler_InvalidLimit(t *testing.T) {
	d := &MockDistributor{}
	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?limit=abc", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Result().StatusCode)
	// The underlying distributor must never be called when the request is
	// rejected for bad parameters.
	d.AssertNotCalled(t, "MetricsMetadata", mock.Anything)
}

func TestMetadataHandler_Error(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return([]scrape.MetricMetadata{}, fmt.Errorf("no user id"))

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	expectedJSON := `
	{
		"status": "error",
		"error": "no user id"
	}
	`

	require.JSONEq(t, expectedJSON, string(responseBody))
}
