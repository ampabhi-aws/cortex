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
			// Truncate the response body before it is logged or written back to
			// the caller. Validation errors can embed tenant-supplied label data
			// that, under adversarial inputs, has reached hundreds of MB; writing
			// that verbatim to the shared process log (holding the synchronous
			// logger mutex) or echoing it to the HTTP response amplifies a small
			// snappy-compressed request into a log/heap DoS.
			msg := string(resp.Body)
			const maxPushErrorMsgLen = 2048
			if len(msg) > maxPushErrorMsgLen {
				msg = msg[:maxPushErrorMsgLen] + "...(truncated)"
			}
			if resp.GetCode() != 202 {
				level.Error(logger).Log("msg", "push error", "err", msg)
			}
			http.Error(w, msg, int(resp.Code))
		}
	})
}
