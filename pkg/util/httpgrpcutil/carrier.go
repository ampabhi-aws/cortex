package httpgrpcutil

import (
	"github.com/opentracing/opentracing-go"
	"github.com/weaveworks/common/httpgrpc"
)

// Used to transfer trace information from/to HTTP request.
type HttpgrpcHeadersCarrier httpgrpc.HTTPRequest

func (c *HttpgrpcHeadersCarrier) Set(key, val string) {
	c.Headers = append(c.Headers, &httpgrpc.Header{
		Key:    key,
		Values: []string{val},
	})
}

func (c *HttpgrpcHeadersCarrier) ForeachKey(handler func(key, val string) error) error {
	for _, h := range c.Headers {
		for _, v := range h.Values {
			if err := handler(h.Key, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func GetParentSpanForRequest(tracer opentracing.Tracer, req *httpgrpc.HTTPRequest) (opentracing.SpanContext, error) {
	if tracer == nil {
		return nil, nil
	}

	carrier := (*HttpgrpcHeadersCarrier)(req)
	extracted, err := tracer.Extract(opentracing.HTTPHeaders, carrier)
	if err != nil {
		// Any extraction error (not just ErrSpanContextNotFound) must be treated
		// as "no parent span". Malformed tracing headers are tenant-controlled
		// input and should not fail the enclosing request. Returning the error
		// here propagates to callers such as Scheduler.enqueueRequest, which
		// surfaces it to the frontend as Status=ERROR.
		return nil, nil
	}
	return extracted, nil
}
