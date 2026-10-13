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

// maxErrorLabelSetLabels bounds how many labels from an offending series are
// retained on a validation error. The message is further truncated by the
// %.200q verb; this cap exists so the error does not retain or format the
// full attacker-sized label slice.
const maxErrorLabelSetLabels = 10

// truncateLabelSetForError returns a copy of ls limited to at most
// maxErrorLabelSetLabels entries. A copy is returned so the error does not
// pin the original (potentially huge) slice.
func truncateLabelSetForError(ls []cortexpb.LabelAdapter) []cortexpb.LabelAdapter {
	if len(ls) <= maxErrorLabelSetLabels {
		out := make([]cortexpb.LabelAdapter, len(ls))
		copy(out, ls)
		return out
	}
	out := make([]cortexpb.LabelAdapter, maxErrorLabelSetLabels)
	copy(out, ls[:maxErrorLabelSetLabels])
	return out
}

type tooManyLabelsError struct {
	// series holds a bounded copy of the offending label set for the error
	// message. actual is the real label count.
	series []cortexpb.LabelAdapter
	actual int
	limit  int
}

func newTooManyLabelsError(series []cortexpb.LabelAdapter, limit int) ValidationError {
	return &tooManyLabelsError{
		series: truncateLabelSetForError(series),
		actual: len(series),
		limit:  limit,
	}
}

func (e *tooManyLabelsError) Error() string {
	// Format only the (already-truncated) sample stored on the error, and apply
	// the same %.200q truncation other validation errors use so the final
	// message cannot be dominated by an attacker-controlled label set.
	return fmt.Sprintf(
		"series has too many labels (actual: %d, limit: %d) series: %.200q",
		e.actual, e.limit, formatLabelSet(e.series))
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
	// Apply the same %.200q truncation other validation errors use. The
	// message format strings used by this error type end with
	// "... series: %s labels: %s"; we substitute %.200q so a huge series
	// label set cannot produce a huge error message.
	msg := strings.Replace(e.message, "series: %s labels: %s", "series: %.200q labels: %.200q", 1)
	return fmt.Sprintf(msg, e.timestamp, formatLabelSet(e.seriesLabels), formatLabelSet(e.exemplarLabels))
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

// formatLabelSetMaxBytes bounds the output size of formatLabelSet so that
// attacker-sized label slices do not produce multi-hundred-megabyte strings
// that are later truncated by %.200q. The value is comfortably larger than
// any %.200q-truncated message a caller could emit.
const formatLabelSetMaxBytes = 1024

// formatLabelSet formats label adapters as a metric name with labels, while preserving
// label order, and keeping duplicates. If there are multiple "__name__" labels, only
// first one is used as metric name, other ones will be included as regular labels.
// It stops appending once the output exceeds formatLabelSetMaxBytes and marks the
// result as truncated, so callers cannot be forced to materialize an unbounded string.
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

	if b.Len() == 0 {
		if hasMetricName {
			return metricName
		}
		return "{}"
	}

	if truncated {
		b.WriteString(", ...")
	}
	return fmt.Sprintf("%s{%s}", metricName, b.String())
}
