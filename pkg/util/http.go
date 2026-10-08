package util

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/opentracing/opentracing-go"
	otlog "github.com/opentracing/opentracing-go/log"
	yaml "gopkg.in/yaml.v2"
	yamlv3 "gopkg.in/yaml.v3"
)

const messageSizeLargerErrFmt = "received message larger than max (%d vs %d)"

// maxPreallocSize is an upper bound on the buffer pre-allocation hint we are
// willing to honour based on client-supplied size signals (e.g. the HTTP
// Content-Length header). Clients can set Content-Length to any value Go's
// net/http accepts without being obliged to actually transmit that many
// bytes, so sizing an allocation directly from it is a cheap
// memory-amplification vector. We cap the hint at 1 MiB and let bytes.Buffer
// grow naturally as data actually arrives.
const maxPreallocSize = 1 << 20 // 1 MiB

// maxSnappyExpansionRatio bounds the ratio between a snappy-decoded payload
// and its compressed form that we are willing to pre-allocate for. The
// snappy format's practical compression ceiling is around 64x; anything
// claiming more than this from a tiny body is almost certainly an attempt
// to force a large allocation ahead of validating the stream.
const maxSnappyExpansionRatio = 64

// IsRequestBodyTooLarge returns true if the error is "http: request body too large".
func IsRequestBodyTooLarge(err error) bool {
	return err != nil && strings.Contains(err.Error(), "http: request body too large")
}

// BasicAuth configures basic authentication for HTTP clients.
type BasicAuth struct {
	Username string `yaml:"basic_auth_username"`
	Password string `yaml:"basic_auth_password"`
}

func (b *BasicAuth) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&b.Username, prefix+"basic-auth-username", "", "HTTP Basic authentication username. It overrides the username set in the URL (if any).")
	f.StringVar(&b.Password, prefix+"basic-auth-password", "", "HTTP Basic authentication password. It overrides the password set in the URL (if any).")
}

// IsEnabled returns false if basic authentication isn't enabled.
func (b BasicAuth) IsEnabled() bool {
	return b.Username != "" || b.Password != ""
}

// WriteJSONResponse writes some JSON as a HTTP response.
func WriteJSONResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")

	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We ignore errors here, because we cannot do anything about them.
	// Write will trigger sending Status code, so we cannot send a different status code afterwards.
	// Also this isn't internal error, but error communicating with client.
	_, _ = w.Write(data)
}

// WriteYAMLResponse writes some YAML as a HTTP response.
func WriteYAMLResponse(w http.ResponseWriter, v interface{}) {
	// There is not standardised content-type for YAML, text/plain ensures the
	// YAML is displayed in the browser instead of offered as a download
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	data, err := yaml.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We ignore errors here, because we cannot do anything about them.
	// Write will trigger sending Status code, so we cannot send a different status code afterwards.
	// Also this isn't internal error, but error communicating with client.
	_, _ = w.Write(data)
}

// Sends message as text/plain response with 200 status code.
func WriteTextResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/plain")

	// Ignore inactionable errors.
	_, _ = w.Write([]byte(message))
}

// Sends message as text/html response with 200 status code.
func WriteHTMLResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html")

	// Ignore inactionable errors.
	_, _ = w.Write([]byte(message))
}

// RenderHTTPResponse either responds with json or a rendered html page using the passed in template
// by checking the Accepts header
func RenderHTTPResponse(w http.ResponseWriter, v interface{}, t *template.Template, r *http.Request) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		WriteJSONResponse(w, v)
		return
	}

	err := t.Execute(w, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StreamWriteYAMLResponseCommon stream writes data as http response
func streamWriteYAMLResponseCommon(w http.ResponseWriter, iter chan interface{}, logger log.Logger, marshalFn func(in interface{}) (out []byte, err error)) {
	w.Header().Set("Content-Type", "application/yaml")
	for v := range iter {
		data, err := marshalFn(v)
		if err != nil {
			level.Error(logger).Log("msg", "yaml marshal failed", "err", err)
			continue
		}
		_, err = w.Write(data)
		if err != nil {
			level.Error(logger).Log("msg", "write http response failed", "err", err)
			return
		}
	}
}

// StreamWriteYAMLResponse stream writes data as http response using yaml v2 library
func StreamWriteYAMLResponse(w http.ResponseWriter, iter chan interface{}, logger log.Logger) {
	streamWriteYAMLResponseCommon(w, iter, logger, yaml.Marshal)
}

// StreamWriteYAMLV3Response stream writes data as http response using yaml v3 library
func StreamWriteYAMLV3Response(w http.ResponseWriter, iter chan interface{}, logger log.Logger) {
	streamWriteYAMLResponseCommon(w, iter, logger, yamlv3.Marshal)
}

// CompressionType for encoding and decoding requests and responses.
type CompressionType int

// Values for CompressionType
const (
	NoCompression CompressionType = iota
	RawSnappy
)

// ParseProtoReader parses a compressed proto from an io.Reader.
func ParseProtoReader(ctx context.Context, reader io.Reader, expectedSize, maxSize int, req proto.Message, compression CompressionType) error {
	sp := opentracing.SpanFromContext(ctx)
	if sp != nil {
		sp.LogFields(otlog.String("event", "util.ParseProtoRequest[start reading]"))
	}
	body, err := decompressRequest(reader, expectedSize, maxSize, compression, sp)
	if err != nil {
		return err
	}

	if sp != nil {
		sp.LogFields(otlog.String("event", "util.ParseProtoRequest[unmarshal]"), otlog.Int("size", len(body)))
	}

	// We re-implement proto.Unmarshal here as it calls XXX_Unmarshal first,
	// which we can't override without upsetting golint.
	req.Reset()
	if u, ok := req.(proto.Unmarshaler); ok {
		err = u.Unmarshal(body)
	} else {
		err = proto.NewBuffer(body).Unmarshal(req)
	}
	if err != nil {
		return err
	}

	return nil
}

func decompressRequest(reader io.Reader, expectedSize, maxSize int, compression CompressionType, sp opentracing.Span) (body []byte, err error) {
	defer func() {
		if err != nil && len(body) > maxSize {
			err = fmt.Errorf(messageSizeLargerErrFmt, len(body), maxSize)
		}
	}()
	if expectedSize > maxSize {
		return nil, fmt.Errorf(messageSizeLargerErrFmt, expectedSize, maxSize)
	}
	buffer, ok := tryBufferFromReader(reader)
	if ok {
		body, err = decompressFromBuffer(buffer, maxSize, compression, sp)
		return
	}
	body, err = decompressFromReader(reader, expectedSize, maxSize, compression, sp)
	return
}

func decompressFromReader(reader io.Reader, expectedSize, maxSize int, compression CompressionType, sp opentracing.Span) ([]byte, error) {
	var (
		buf  bytes.Buffer
		body []byte
		err  error
	)
	if expectedSize > 0 {
		// Do NOT trust expectedSize (which is derived from the client-controlled
		// Content-Length header on the HTTP push path) to size the allocation
		// up-front. A malicious client can set Content-Length to the configured
		// maxSize and never actually send the bytes, which would force us to
		// pre-allocate ~maxSize of heap per connection before any body byte is
		// read. Clamp the hint to maxPreallocSize and let bytes.Buffer grow
		// naturally as data arrives.
		hint := expectedSize
		if hint > maxPreallocSize {
			hint = maxPreallocSize
		}
		buf.Grow(hint + bytes.MinRead)
	}
	// Read from LimitReader with limit max+1. So if the underlying
	// reader is over limit, the result will be bigger than max.
	reader = io.LimitReader(reader, int64(maxSize)+1)
	switch compression {
	case NoCompression:
		_, err = buf.ReadFrom(reader)
		body = buf.Bytes()
	case RawSnappy:
		_, err = buf.ReadFrom(reader)
		if err != nil {
			return nil, err
		}
		body, err = decompressFromBuffer(&buf, maxSize, RawSnappy, sp)
	}
	return body, err
}

func decompressFromBuffer(buffer *bytes.Buffer, maxSize int, compression CompressionType, sp opentracing.Span) ([]byte, error) {
	if len(buffer.Bytes()) > maxSize {
		return nil, fmt.Errorf(messageSizeLargerErrFmt, len(buffer.Bytes()), maxSize)
	}
	switch compression {
	case NoCompression:
		return buffer.Bytes(), nil
	case RawSnappy:
		if sp != nil {
			sp.LogFields(otlog.String("event", "util.ParseProtoRequest[decompress]"),
				otlog.Int("size", len(buffer.Bytes())))
		}
		size, err := snappy.DecodedLen(buffer.Bytes())
		if err != nil {
			return nil, err
		}
		if size > maxSize {
			return nil, fmt.Errorf(messageSizeLargerErrFmt, size, maxSize)
		}
		// Reject implausible expansion ratios before calling snappy.Decode,
		// which allocates `size` bytes via make([]byte, dLen) BEFORE validating
		// the compressed stream. The snappy format's practical compression
		// ceiling is ~64x, so a decoded length wildly larger than
		// maxSnappyExpansionRatio * len(compressed) can only be an attempt to
		// force a large allocation from a tiny body.
		if compressed := len(buffer.Bytes()); compressed > 0 && size/maxSnappyExpansionRatio > compressed {
			return nil, fmt.Errorf("snappy decoded length %d implausible for %d compressed bytes", size, compressed)
		}
		body, err := snappy.Decode(nil, buffer.Bytes())
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, nil
}

// tryBufferFromReader attempts to cast the reader to a `*bytes.Buffer` this is possible when using httpgrpc.
// If it fails it will return nil and false.
func tryBufferFromReader(reader io.Reader) (*bytes.Buffer, bool) {
	if bufReader, ok := reader.(interface {
		BytesBuffer() *bytes.Buffer
	}); ok && bufReader != nil {
		return bufReader.BytesBuffer(), true
	}
	return nil, false
}

// SerializeProtoResponse serializes a protobuf response into an HTTP response.
func SerializeProtoResponse(w http.ResponseWriter, resp proto.Message, compression CompressionType) error {
	data, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return fmt.Errorf("error marshaling proto response: %v", err)
	}

	switch compression {
	case NoCompression:
	case RawSnappy:
		data = snappy.Encode(nil, data)
	}

	if _, err := w.Write(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return fmt.Errorf("error sending proto response: %v", err)
	}
	return nil
}
