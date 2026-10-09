package validation

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/common/model"

	"github.com/cortexproject/cortex/pkg/cortexpb"
)

// ValidationError is an error returned by series validation.
//
// Ignore stutter warning.
// nolint:revive
type ValidationError error

// genericValidationError is a basic implementation of ValidationError which can be used when the
// error format only contains the cause and the series.
type genericValidationError struct {
	message string
	cause   string
	series  []cortexpb.LabelAdapter
}

func (e *genericValidationError) Error() string {
	return fmt.Sprintf(e.message, e.cause, formatLabelSet(e.series))
}

// labelNameTooLongError is a customized ValidationError, in that the cause and the series are
// formatted in different order in Error.
type labelNameTooLongError struct {
	labelName string
	series    []cortexpb.LabelAdapter
	limit     int
}

func (e *labelNameTooLongError) Error() string {
	return fmt.Sprintf("label name too long for metric (actual: %d, limit: %d) metric: %.200q label name: %.200q", len(e.labelName), e.limit, formatLabelSet(e.series), e.labelName)
}

func newLabelNameTooLongError(series []cortexpb.LabelAdapter, labelName string, limit int) ValidationError {
	return &labelNameTooLongError{
		labelName: labelName,
		series:    series,
		limit:     limit,
	}
}

// labelValueTooLongError is a customized ValidationError, in that the cause and the series are
// formatted in different order in Error.
type labelValueTooLongError struct {
	labelName  string
	labelValue string
	series     []cortexpb.LabelAdapter
	limit      int
}

func (e *labelValueTooLongError) Error() string {
	return fmt.Sprintf("label value too long for metric (actual: %d, limit: %d) metric: %.200q label name: %.200q label value: %.200q",
		len(e.labelValue), e.limit, formatLabelSet(e.series), e.labelName, e.labelValue)
}

func newLabelValueTooLongError(series []cortexpb.LabelAdapter, labelName, labelValue string, limit int) ValidationError {
	return &labelValueTooLongError{
		labelName:  labelName,
		labelValue: labelValue,
		series:     series,
		limit:      limit,
	}
}

// labelsSizeBytesExceededError is a customized ValidationError, in that the cause and the series are
// formatted in different order in Error.
type labelsSizeBytesExceededError struct {
	labelsSizeBytes int
	series          []cortexpb.LabelAdapter
	limit           int
}

func (e *labelsSizeBytesExceededError) Error() string {
	return fmt.Sprintf("labels size bytes exceeded for metric (actual: %d, limit: %d) metric: %.200q", e.labelsSizeBytes, e.limit, formatLabelSet(e.series))
}

func labelSizeBytesExceededError(series []cortexpb.LabelAdapter, labelsSizeBytes int, limit int) ValidationError {
	return &labelsSizeBytesExceededError{
		labelsSizeBytes: labelsSizeBytes,
		series:          series,
		limit:           limit,
	}
}

func newInvalidLabelError(series []cortexpb.LabelAdapter, labelName string) ValidationError {
	return &genericValidationError{
		message: "sample invalid label: %.200q metric %.200q",
		cause:   labelName,
		series:  series,
	}
}

func newDuplicatedLabelError(series []cortexpb.LabelAdapter, labelName string) ValidationError {
	return &genericValidationError{
		message: "duplicate label name: %.200q metric %.200q",
		cause:   labelName,
		series:  series,
	}
}

func newLabelsNotSortedError(series []cortexpb.LabelAdapter, labelName string) ValidationError {
	return &genericValidationError{
		message: "labels not sorted: %.200q metric %.200q",
		cause:   labelName,
		series:  series,
	}
}

type tooManyLabelsError struct {
	series []cortexpb.LabelAdapter
	limit  int
}

func newTooManyLabelsError(series []cortexpb.LabelAdapter, limit int) ValidationError {
	return &tooManyLabelsError{
		series: series,
		limit:  limit,
	}
}

func (e *tooManyLabelsError) Error() string {
	// Match the clamping used by the other validation errors in this file so a
	// tenant-controlled label set cannot produce an unbounded error string.
	return fmt.Sprintf(
		"series has too many labels (actual: %d, limit: %d) series: %.200q",
		len(e.series), e.limit, formatLabelSet(e.series))
}

type noMetricNameError struct{}

func newNoMetricNameError() ValidationError {
	return &noMetricNameError{}
}

func (e *noMetricNameError) Error() string {
	return "sample missing metric name"
}

type invalidMetricNameError struct {
	metricName string
}

func newInvalidMetricNameError(metricName string) ValidationError {
	return &invalidMetricNameError{
		metricName: metricName,
	}
}

func (e *invalidMetricNameError) Error() string {
	return fmt.Sprintf("sample invalid metric name: %.200q", e.metricName)
}

// sampleValidationError is a ValidationError implementation suitable for sample validation errors.
type sampleValidationError struct {
	message    string
	metricName string
	timestamp  int64
}

func (e *sampleValidationError) Error() string {
	return fmt.Sprintf(e.message, e.timestamp, e.metricName)
}

func newSampleTimestampTooOldError(metricName string, timestamp int64) ValidationError {
	return &sampleValidationError{
		message:    "timestamp too old: %d metric: %.200q",
		metricName: metricName,
		timestamp:  timestamp,
	}
}

func newSampleTimestampTooNewError(metricName string, timestamp int64) ValidationError {
	return &sampleValidationError{
		message:    "timestamp too new: %d metric: %.200q",
		metricName: metricName,
		timestamp:  timestamp,
	}
}

// exemplarValidationError is a ValidationError implementation suitable for exemplar validation errors.
type exemplarValidationError struct {
	message        string
	seriesLabels   []cortexpb.LabelAdapter
	exemplarLabels []cortexpb.LabelAdapter
	timestamp      int64
}

func (e *exemplarValidationError) Error() string {
	// Clamp the rendered label sets to a safe bound to avoid echoing unbounded
	// tenant-supplied data into logs/responses. The sibling series validation
	// errors in this file use the same %.200q pattern.
	return fmt.Sprintf(e.message, e.timestamp, truncateString(cortexpb.FromLabelAdaptersToLabels(e.seriesLabels).String(), 200), truncateString(cortexpb.FromLabelAdaptersToLabels(e.exemplarLabels).String(), 200))
}

func newExemplarEmtpyLabelsError(seriesLabels []cortexpb.LabelAdapter, exemplarLabels []cortexpb.LabelAdapter, timestamp int64) ValidationError {
	return &exemplarValidationError{
		message:        "exemplar missing labels, timestamp: %d series: %s labels: %s",
		seriesLabels:   seriesLabels,
		exemplarLabels: exemplarLabels,
		timestamp:      timestamp,
	}
}

func newExemplarMissingTimestampError(seriesLabels []cortexpb.LabelAdapter, exemplarLabels []cortexpb.LabelAdapter, timestamp int64) ValidationError {
	return &exemplarValidationError{
		message:        "exemplar missing timestamp, timestamp: %d series: %s labels: %s",
		seriesLabels:   seriesLabels,
		exemplarLabels: exemplarLabels,
		timestamp:      timestamp,
	}
}

var labelLenMsg = "exemplar combined labelset exceeds " + strconv.Itoa(ExemplarMaxLabelSetLength) + " characters, timestamp: %d series: %s labels: %s"

func newExemplarLabelLengthError(seriesLabels []cortexpb.LabelAdapter, exemplarLabels []cortexpb.LabelAdapter, timestamp int64) ValidationError {
	return &exemplarValidationError{
		message:        labelLenMsg,
		seriesLabels:   seriesLabels,
		exemplarLabels: exemplarLabels,
		timestamp:      timestamp,
	}
}

// formatLabelSetMaxBytes bounds how many bytes formatLabelSet may build up
// before it stops appending additional labels. It only exists to defend against
// attacker-controlled label sets whose rendered form would otherwise consume
// hundreds of megabytes of transient heap before the caller clamps the result
// (e.g. with %.200q). The value is well above any sensible metric size.
const formatLabelSetMaxBytes = 1024

// formatLabelSet formats label adapters as a metric name with labels, while preserving
// label order, and keeping duplicates. If there are multiple "__name__" labels, only
// first one is used as metric name, other ones will be included as regular labels.
//
// The formatter stops appending further labels once its internal buffer exceeds
// formatLabelSetMaxBytes so that callers rendering untrusted label sets cannot
// trigger unbounded heap allocation before the usual %.200q clamp fires.
func formatLabelSet(ls []cortexpb.LabelAdapter) string {
	metricName, hasMetricName := "", false

	var b strings.Builder
	first := true
	truncated := false
	for _, l := range ls {
		if l.Name == model.MetricNameLabel && !hasMetricName && l.Value != "" {
			metricName = l.Value
			hasMetricName = true
			continue
		}
		if b.Len() >= formatLabelSetMaxBytes {
			truncated = true
			break
		}
		if !first {
			b.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&b, "%s=%q", l.Name, l.Value)
	}
	if truncated {
		if !first {
			b.WriteString(", ")
		}
		b.WriteString("...")
	}

	if b.Len() == 0 {
		if hasMetricName {
			return metricName
		}
		return "{}"
	}

	return fmt.Sprintf("%s{%s}", metricName, b.String())
}

// truncateString returns s truncated to at most n bytes, appending an ellipsis
// marker when truncation occurred. It is used to bound tenant-controlled
// strings that are embedded directly into error messages without a %.NNq clamp.
func truncateString(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
