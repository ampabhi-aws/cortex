package httpgrpcutil

import (
	"strings"

	"github.com/opentracing/opentracing-go"
	"github.com/weaveworks/common/httpgrpc"
)

// Used to transfer trace information from/to HTTP request.
type HttpgrpcHeadersCarrier httpgrpc.HTTPRequest

func (c *HttpgrpcHeadersCarrier) Set(key, val string) {
	// Replace any existing values for this key (case-insensitive match on the
	// HTTP header name) rather than appending. This prevents a client-supplied
	// value (e.g. a malformed uber-trace-id) from being carried alongside the
	// value we inject here when the carrier is used to propagate trace context.
	for _, h := range c.Headers {
		if strings.EqualFold(h.Key, key) {
			h.Key = key
			h.Values = []string{val}
			return
		}
	}
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
	if err == opentracing.ErrSpanContextNotFound {
		err = nil
	}
	return extracted, err
}
