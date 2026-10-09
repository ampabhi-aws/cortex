package log

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestHeaderMapFromMetadata(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation", "TestHeader2", "ContentsOfTestHeader2")

	ctx := context.Background()

	allowed := []string{"TestHeader1", "TestHeader2"}
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, allowed)

	headerMap := HeaderMapFromContext(ctx)

	require.Contains(t, headerMap, "TestHeader1")
	require.Contains(t, headerMap, "TestHeader2")
	require.Equal(t, "SomeInformation", headerMap["TestHeader1"])
	require.Equal(t, "ContentsOfTestHeader2", headerMap["TestHeader2"])
}

func TestHeaderMapFromMetadataWithImproperLength(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation", "TestHeader2", "ContentsOfTestHeader2", "Test3")

	ctx := context.Background()

	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"TestHeader1", "TestHeader2", "Test3"})

	headerMap := HeaderMapFromContext(ctx)
	require.Nil(t, headerMap)
}

func TestHeaderMapFromMetadataFiltersAgainstAllowlist(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation", "attacker_key", "attacker_value")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"TestHeader1"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, 1, len(headerMap))
	require.Equal(t, "SomeInformation", headerMap["TestHeader1"])
}

func TestHeaderMapFromMetadataRejectsInvalidLogKeys(t *testing.T) {
	md := metadata.New(nil)
	// A single '=' would be stripped by logfmt's keyRuneFilter and cause the whole log record to be dropped.
	md.Append(HeaderPropagationStringForRequestLogging, "=", "x")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"="})

	require.Nil(t, HeaderMapFromContext(ctx))
}

func TestHeaderMapFromMetadataEmptyAllowlist(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, nil)

	require.Nil(t, HeaderMapFromContext(ctx))
}

func TestInjectHeadersIntoHTTPRequest(t *testing.T) {
	contentsMap := make(map[string]string)
	contentsMap["TestHeader1"] = "RequestID"
	contentsMap["TestHeader2"] = "ContentsOfTestHeader2"

	h := http.Header{}
	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     h,
	}
	InjectHeadersIntoHTTPRequest(contentsMap, req)

	header1 := req.Header.Values("TestHeader1")
	header2 := req.Header.Values("TestHeader2")

	require.NotNil(t, header1)
	require.NotNil(t, header2)
	require.Equal(t, 1, len(header1))
	require.Equal(t, 1, len(header2))

	require.Equal(t, "RequestID", header1[0])
	require.Equal(t, "ContentsOfTestHeader2", header2[0])
}

func TestInjectHeadersIntoHTTPRequestWithAllowlist(t *testing.T) {
	contentsMap := map[string]string{
		"TestHeader1": "RequestID",
		"X-Injected":  "attacker",
	}

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     http.Header{},
	}
	InjectHeadersIntoHTTPRequest(contentsMap, req, []string{"TestHeader1"})

	require.Equal(t, "RequestID", req.Header.Get("TestHeader1"))
	require.Equal(t, "", req.Header.Get("X-Injected"))
}

func TestIsValidLogKey(t *testing.T) {
	require.True(t, IsValidLogKey("X-Request-ID"))
	require.True(t, IsValidLogKey("abc"))
	require.False(t, IsValidLogKey("="))
	require.False(t, IsValidLogKey(" "))
	require.False(t, IsValidLogKey("\""))
	require.False(t, IsValidLogKey(""))
}
