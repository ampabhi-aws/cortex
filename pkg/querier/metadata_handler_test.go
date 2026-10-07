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
			{Metric: "metric_a", Help: "a", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "b", Type: "gauge", Unit: ""},
			{Metric: "metric_c", Help: "c", Type: "gauge", Unit: ""},
		},
		nil)

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?limit=2", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	var got metadataResult
	require.NoError(t, json.Unmarshal(responseBody, &got))
	require.Equal(t, statusSuccess, got.Status)
	require.Len(t, got.Data, 2)
}

func TestMetadataHandler_LimitPerMetric(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return(
		[]scrape.MetricMetadata{
			{Metric: "metric_a", Help: "a1", Type: "gauge", Unit: ""},
			{Metric: "metric_a", Help: "a2", Type: "gauge", Unit: ""},
			{Metric: "metric_a", Help: "a3", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "b1", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "b2", Type: "gauge", Unit: ""},
		},
		nil)

	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?limit_per_metric=1", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	responseBody, err := io.ReadAll(recorder.Result().Body)
	require.NoError(t, err)

	var got metadataResult
	require.NoError(t, json.Unmarshal(responseBody, &got))
	require.Equal(t, statusSuccess, got.Status)
	require.Len(t, got.Data, 2)
	require.Len(t, got.Data["metric_a"], 1)
	require.Len(t, got.Data["metric_b"], 1)
}

func TestMetadataHandler_MetricFilter(t *testing.T) {
	d := &MockDistributor{}
	d.On("MetricsMetadata", mock.Anything).Return(
		[]scrape.MetricMetadata{
			{Metric: "metric_a", Help: "a", Type: "gauge", Unit: ""},
			{Metric: "metric_b", Help: "b", Type: "gauge", Unit: ""},
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

	var got metadataResult
	require.NoError(t, json.Unmarshal(responseBody, &got))
	require.Equal(t, statusSuccess, got.Status)
	require.Len(t, got.Data, 1)
	_, ok := got.Data["metric_b"]
	require.True(t, ok)
}

func TestMetadataHandler_InvalidLimit(t *testing.T) {
	d := &MockDistributor{}
	handler := MetadataHandler(d)

	request, err := http.NewRequest("GET", "/metadata?limit=notanumber", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Result().StatusCode)
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
