package push

import (
	"context"
	"net/http"

	"github.com/go-kit/log/level"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/middleware"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/log"
)

// Func defines the type of the push. It is similar to http.HandlerFunc.
type Func func(context.Context, *cortexpb.WriteRequest) (*cortexpb.WriteResponse, error)

// maxLoggedErrorBytes bounds how many bytes of an error are written to the log line
// emitted by Handler. Validation errors in the push pipeline are formatted from
// attacker-controlled label data, so an unbounded log write can flood the shared
// logging pipeline on the distributor.
const maxLoggedErrorBytes = 1024

// truncateErrorForLog returns a string representation of err suitable for logging,
// bounded to maxLoggedErrorBytes. It avoids materializing more than that many bytes
// in the final log line even if err.Error() is very large.
func truncateErrorForLog(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) <= maxLoggedErrorBytes {
		return s
	}
	return s[:maxLoggedErrorBytes] + "... (truncated)"
}

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
			if resp.GetCode() != 202 {
				// Cap the error message that is written to the log line. Validation errors
				// are built from attacker-controlled series/label data; without a cap one
				// malformed request can flood the shared logging pipeline.
				level.Error(logger).Log("msg", "push error", "err", truncateErrorForLog(err))
			}
			http.Error(w, string(resp.Body), int(resp.Code))
		}
	})
}
