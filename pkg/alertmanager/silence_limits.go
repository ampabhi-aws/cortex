// SPDX-License-Identifier: Apache-2.0

package alertmanager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-openapi/strfmt"
	v2_models "github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/silence"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// silenceLimiter enforces per-tenant limits on silences before they enter the replicated state.
// Unlike alerts, upstream silences expose no store callback, so limits are enforced at the HTTP
// layer by intercepting the POST /api/v{1,2}/silences handler.
type silenceLimiter struct {
	tenant   string
	limits   Limits
	silences *silence.Silences
	logger   log.Logger

	rejected prometheus.Counter
	clamped  prometheus.Counter
}

func newSilenceLimiter(tenant string, limits Limits, silences *silence.Silences, logger log.Logger, reg prometheus.Registerer) *silenceLimiter {
	return &silenceLimiter{
		tenant:   tenant,
		limits:   limits,
		silences: silences,
		logger:   logger,
		rejected: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_silences_insert_limited_total",
			Help: "Number of silences rejected because they exceeded per-tenant silence limits.",
		}),
		clamped: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_silences_duration_clamped_total",
			Help: "Number of silences whose EndsAt was clamped to the configured maximum silence duration.",
		}),
	}
}

// wrap returns an http.Handler that enforces silence limits before delegating to next.
// The returned handler only validates POST requests whose path ends in /silences; all other
// requests are forwarded unchanged.
func (l *silenceLimiter) wrap(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSilencePostPath(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Read the body up to a safe cap. We intentionally cap size here regardless of
		// -alertmanager.max-recv-msg-size so the per-silence byte limit is independent of
		// per-request transport ceilings. The cap is 2x the configured max silence size
		// (so JSON overhead doesn't cause spurious failures) or 1 MiB when disabled.
		sizeLimit := l.limits.AlertmanagerMaxSilenceSizeBytes(l.tenant)
		readCap := int64(16 * 1024 * 1024)
		if sizeLimit > 0 {
			// Allow ~2x for JSON overhead vs. internal size accounting.
			readCap = int64(sizeLimit) * 2
			if readCap < 64*1024 {
				readCap = 64 * 1024
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, readCap+1))
		if err != nil {
			http.Error(w, "failed to read silence body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > readCap {
			l.rejected.Inc()
			http.Error(w, fmt.Sprintf("silence payload exceeds max size (%d bytes)", sizeLimit), http.StatusRequestEntityTooLarge)
			return
		}

		var postable v2_models.PostableSilence
		if err := postable.UnmarshalBinary(body); err != nil {
			// Fall through — let upstream return its native 400 to preserve existing error shape.
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r)
			return
		}

		// Enforce per-silence payload size independent of transport.
		if sizeLimit > 0 {
			if sz := silencePayloadSize(&postable); sz > sizeLimit {
				l.rejected.Inc()
				level.Warn(l.logger).Log("msg", "rejecting silence: exceeds max size", "tenant", l.tenant, "size", sz, "limit", sizeLimit)
				http.Error(w, fmt.Sprintf("silence too big, size limit: %d bytes", sizeLimit), http.StatusBadRequest)
				return
			}
		}

		// Enforce per-tenant silence count. We count only active and pending silences — expired
		// silences are already GC candidates and do not keep heap after their ExpiresAt. If the
		// request updates an existing silence (ID present), it does not increase the count.
		countLimit := l.limits.AlertmanagerMaxSilencesCount(l.tenant)
		if countLimit > 0 && postable.ID == "" {
			if current, err := l.silences.CountState(types.SilenceStateActive, types.SilenceStatePending); err == nil {
				if current+1 > countLimit {
					l.rejected.Inc()
					level.Warn(l.logger).Log("msg", "rejecting silence: exceeds max count", "tenant", l.tenant, "current", current, "limit", countLimit)
					http.Error(w, fmt.Sprintf("too many silences, limit: %d", countLimit), http.StatusBadRequest)
					return
				}
			}
		}

		// Clamp attacker-chosen EndsAt to a maximum silence duration to cap retention impact.
		if maxDur := l.limits.AlertmanagerMaxSilenceDuration(l.tenant); maxDur > 0 && postable.EndsAt != nil {
			start := time.Now()
			if postable.StartsAt != nil {
				if t := time.Time(*postable.StartsAt); !t.IsZero() {
					start = t
				}
			}
			maxEnd := start.Add(maxDur)
			if time.Time(*postable.EndsAt).After(maxEnd) {
				clamped := strfmt.DateTime(maxEnd)
				postable.EndsAt = &clamped
				l.clamped.Inc()
				level.Info(l.logger).Log("msg", "clamped silence EndsAt to max duration", "tenant", l.tenant, "max_duration", maxDur)
				// Re-serialize with the clamped EndsAt so the downstream handler sees it.
				newBody, err := json.Marshal(&postable)
				if err == nil {
					body = newBody
				}
			}
		}

		// Hand the (possibly rewritten) body to the next handler.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

// isSilencePostPath returns true for POST /…/api/v{1,2}/silences — the paths that create or
// update silences in the Alertmanager API.
func isSilencePostPath(method, p string) bool {
	if method != http.MethodPost {
		return false
	}
	return strings.HasSuffix(p, "/silences")
}

// silencePayloadSize returns the number of attacker-controlled bytes in a silence payload.
// It is used for the per-silence size limit and must stay independent of JSON representation
// overhead so operator-chosen limits are meaningful.
func silencePayloadSize(s *v2_models.PostableSilence) int {
	size := 0
	if s.Comment != nil {
		size += len(*s.Comment)
	}
	if s.CreatedBy != nil {
		size += len(*s.CreatedBy)
	}
	for _, m := range s.Matchers {
		if m == nil {
			continue
		}
		if m.Name != nil {
			size += len(*m.Name)
		}
		if m.Value != nil {
			size += len(*m.Value)
		}
	}
	return size
}
