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

// maxErrMsgLen bounds the size of the error text that Handler logs and writes
// to the HTTP response body. This caps the amplification an attacker can cause
// by sending a push request whose validation error wraps a large
// attacker-controlled label set.
const maxErrMsgLen = 1024

// truncateErrMsg clamps an error message to maxErrMsgLen bytes to avoid
// writing arbitrarily large attacker-controlled strings to logs and the
// HTTP response body.
func truncateErrMsg(s string) string {
	if len(s) <= maxErrMsgLen {
		return s
	}
	return s[:maxErrMsgLen] + "... (truncated)"
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
				http.Error(w, truncateErrMsg(err.Error()), http.StatusInternalServerError)
				return
			}
			body := truncateErrMsg(string(resp.Body))
			if resp.GetCode() != 202 {
				level.Error(logger).Log("msg", "push error", "err", body)
			}
			http.Error(w, body, int(resp.Code))
		}
	})
}
