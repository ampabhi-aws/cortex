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

// AdmissionController, when non-nil, is consulted by Handler before any body
// bytes are read or buffers are allocated. If it returns a non-nil error, the
// request is rejected immediately with the supplied HTTP status code and no
// decoding/allocation is performed. This exists so that instance-level limits
// (for example a distributor's MaxInflightPushRequests) can gate requests
// before the body-sized pre-allocation inside util.ParseProtoReader, closing
// the memory-amplification DoS where ~headers reserve maxRecvMsgSize of heap
// per connection (CWE-770).
type AdmissionController func(ctx context.Context, r *http.Request) (status int, err error)

// Handler is a http.Handler which accepts WriteRequests.
func Handler(maxRecvMsgSize int, sourceIPs *middleware.SourceIPExtractor, push Func) http.Handler {
	return handler(maxRecvMsgSize, sourceIPs, nil, push)
}

// HandlerWithAdmission is like Handler but consults the supplied
// AdmissionController before reading or allocating anything for the request
// body. Prefer this variant from callers that have access to a per-instance
// inflight/rate limiter so that over-limit requests are rejected without
// committing heap for the body.
func HandlerWithAdmission(maxRecvMsgSize int, sourceIPs *middleware.SourceIPExtractor, admit AdmissionController, push Func) http.Handler {
	return handler(maxRecvMsgSize, sourceIPs, admit, push)
}

func handler(maxRecvMsgSize int, sourceIPs *middleware.SourceIPExtractor, admit AdmissionController, push Func) http.Handler {
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
		// Admission control runs before ParseProtoReader so that
		// over-limit requests cannot pre-allocate the body buffer.
		if admit != nil {
			if status, err := admit(ctx, r); err != nil {
				level.Error(logger).Log("err", err.Error())
				http.Error(w, err.Error(), status)
				return
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
				level.Error(logger).Log("msg", "push error", "err", err)
			}
			http.Error(w, string(resp.Body), int(resp.Code))
		}
	})
}
