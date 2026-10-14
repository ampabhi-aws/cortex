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
	// Render only a bounded prefix of the attacker-controlled label set to avoid
	// turning a large but otherwise valid-looking push request into a multi-GiB
	// allocation and a ~100 MiB log line. ValidateLabels returns this error
	// before any per-label length check has run, so e.series is unbounded in
	// both label count and per-label size: we must not materialise it in full.
	return fmt.Sprintf(
		"series has too many labels (actual: %d, limit: %d) series: %.200q",
		len(e.series), e.limit, formatLabelSetBounded(e.series, 200))
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
	// Bound the rendered label sets: ValidateExemplar is reached with the
	// series' full unvalidated label set, which may contain millions of labels.
	// Without truncation this error would produce multi-GiB output.
	return fmt.Sprintf(e.message, e.timestamp, formatLabelSetBounded(e.seriesLabels, 200), formatLabelSetBounded(e.exemplarLabels, 200))
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

// formatLabelSet formats label adapters as a metric name with labels, while preserving
// label order, and keeping duplicates. If there are multiple "__name__" labels, only
// first one is used as metric name, other ones will be included as regular labels.
func formatLabelSet(ls []cortexpb.LabelAdapter) string {
	metricName, hasMetricName := "", false

	labelStrings := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Name == model.MetricNameLabel && !hasMetricName && l.Value != "" {
			metricName = l.Value
			hasMetricName = true
		} else {
			labelStrings = append(labelStrings, fmt.Sprintf("%s=%q", l.Name, l.Value))
		}
	}

	if len(labelStrings) == 0 {
		if hasMetricName {
			return metricName
		}
		return "{}"
	}

	return fmt.Sprintf("%s{%s}", metricName, strings.Join(labelStrings, ", "))
}

// formatLabelSetBounded is a defensive variant of formatLabelSet used on error
// paths where the label set is attacker-controlled and may be arbitrarily
// large (e.g. tooManyLabelsError, exemplarValidationError reached before any
// per-label length check has run). It stops rendering once the accumulated
// output would exceed maxBytes, appending an ellipsis and the remaining label
// count instead. This keeps error formatting O(min(N, maxBytes)) in both time
// and allocation, so a push request with millions of labels cannot drive
// multi-GiB allocation or ~100 MiB log lines through a single Error() call.
func formatLabelSetBounded(ls []cortexpb.LabelAdapter, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 200
	}

	metricName, hasMetricName := "", false
	var sb strings.Builder
	// Pre-size a little above maxBytes to accommodate the closing brace and the
	// truncation suffix without re-allocating.
	sb.Grow(maxBytes + 32)

	writtenLabels := 0
	totalLabels := 0
	truncated := false

	for _, l := range ls {
		if l.Name == model.MetricNameLabel && !hasMetricName && l.Value != "" {
			metricName = l.Value
			hasMetricName = true
			continue
		}
		totalLabels++
		if truncated {
			continue
		}
		if sb.Len() >= maxBytes {
			truncated = true
			continue
		}
		if writtenLabels == 0 {
			sb.WriteString(metricName)
			sb.WriteByte('{')
		} else {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%s=%q", l.Name, l.Value)
		writtenLabels++
	}

	if writtenLabels == 0 {
		if hasMetricName {
			return metricName
		}
		return "{}"
	}

	if truncated {
		fmt.Fprintf(&sb, ", ...and %d more", totalLabels-writtenLabels)
	}
	sb.WriteByte('}')
	return sb.String()
}
