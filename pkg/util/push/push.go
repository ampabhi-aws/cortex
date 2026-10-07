package push

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/log"
)

// maxPushErrorBodyBytes caps the size of a push error body that we log at
// error level and echo back to the HTTP client. Error paths can carry
// attacker-controlled label text (see pkg/util/validation/errors.go); the
// renderers themselves clamp with %.200q, but we clamp again here as a
// belt-and-braces defence against any future unbounded error renderer and
// against the fact that the body is both logged (via logfmt-escaped level.Error)
// and copied into the HTTP response.
const maxPushErrorBodyBytes = 4 * 1024

// truncatePushErrorBody returns body as-is when it is within the configured
// cap, otherwise it returns the first maxPushErrorBodyBytes bytes followed by
// a marker indicating how many bytes were elided.
func truncatePushErrorBody(body []byte) []byte {
	if len(body) <= maxPushErrorBodyBytes {
		return body
	}
	elided := len(body) - maxPushErrorBodyBytes
	return []byte(fmt.Sprintf("%s... (truncated, %d more bytes elided)", body[:maxPushErrorBodyBytes], elided))
}

// Func defines the type of the push. It is similar to http.HandlerFunc.
type Func func(context.Context, *cortexpb.WriteRequest) (*cortexpb.WriteResponse, error)

// Handler is a http.Handler which accepts WriteRequests.
func Handler(maxRecvMsgSize int, sourceIPs *middleware.SourceIPExtractor, push Func) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.WithContext(ctx, log.Logger)
		if sourceIPs != nil {
			source := sourceIPs.Get(r)
			if source != "" {
				ctx = util.AddSourceIPsToOutgoingContext(ctx, source)
				logger = log.WithSourceIPs(source, logger)
			}
		}
		var req cortexpb.PreallocWriteRequest
		err := util.ParseProtoReader(ctx, r.Body, int(r.ContentLength), maxRecvMsgSize, &req, util.RawSnappy)
		if err != nil {
			level.Error(logger).Log("err", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		req.SkipLabelNameValidation = false
		if req.Source == 0 {
			req.Source = cortexpb.API
		}

		if _, err := push(ctx, &req.WriteRequest); err != nil {
			resp, ok := httpgrpc.HTTPResponseFromError(err)
			if !ok {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Cap the size of the error body before logging and echoing it back
			// to the caller: a validation error on a hostile series could
			// otherwise force a multi-MB log record and HTTP response body.
			body := truncatePushErrorBody(resp.Body)
			if resp.GetCode() != 202 {
				level.Error(logger).Log("msg", "push error", "err", string(body))
			}
			http.Error(w, string(body), int(resp.Code))
		}
	})
}
