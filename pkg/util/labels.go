package util

import (
	"strings"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

// labelsToMetricMaxSizeHint caps the map pre-size hint used by LabelsToMetric
// so that attacker-controlled label counts cannot force a huge up-front map
// allocation (buckets are allocated eagerly from the size hint).
const labelsToMetricMaxSizeHint = 1024

// LabelsToMetric converts a Labels to Metric
// Don't do this on any performance sensitive paths.
func LabelsToMetric(ls labels.Labels) model.Metric {
	// Cap the pre-size hint: callers may pass untrusted-length label sets.
	sizeHint := len(ls)
	if sizeHint > labelsToMetricMaxSizeHint {
		sizeHint = labelsToMetricMaxSizeHint
	}
	m := make(model.Metric, sizeHint)
	for _, l := range ls {
		m[model.LabelName(l.Name)] = model.LabelValue(l.Value)
	}
	return m
}

// LabelMatchersToString returns a string representing the input label matchers.
func LabelMatchersToString(matchers []*labels.Matcher) string {
	out := strings.Builder{}
	out.WriteRune('{')

	for idx, m := range matchers {
		if idx > 0 {
			out.WriteRune(',')
		}

		out.WriteString(m.String())
	}

	out.WriteRune('}')
	return out.String()
}
