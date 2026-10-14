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
			if resp.GetCode() != 202 {
				// Error bodies on this path include attacker-controlled validation
				// messages (e.g. rendered label sets). Truncate what we log so a
				// single malformed push can't write ~100 MiB per request into the
				// operator's logging pipeline.
				level.Error(logger).Log("msg", "push error", "err", truncateErrorForLog(err))
			}
			http.Error(w, string(resp.Body), int(resp.Code))
		}
	})
}

// maxErrorLogBodyLen bounds the number of bytes of an attacker-influenced error
// message that we are willing to copy into the process log. 1 KiB is more than
// enough to retain the diagnostic prefix (status code, validation reason,
// bounded label set) that validation errors emit.
const maxErrorLogBodyLen = 1024

// truncateErrorForLog returns an error whose Error() string is capped at
// maxErrorLogBodyLen bytes, suitable for logging without copying a large
// attacker-controlled message into log storage. The original error is left
// intact for the HTTP response and the gRPC status.
func truncateErrorForLog(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if len(msg) <= maxErrorLogBodyLen {
		return err
	}
	return fmt.Errorf("%s... (truncated, original length: %d)", msg[:maxErrorLogBodyLen], len(msg))
}
