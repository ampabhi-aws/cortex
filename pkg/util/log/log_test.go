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

	// Without an allowlist (legacy behaviour) all pairs are accepted.
	ctx = ContextWithHeaderMapFromMetadata(ctx, md)

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

	ctx = ContextWithHeaderMapFromMetadata(ctx, md)

	headerMap := HeaderMapFromContext(ctx)
	require.Nil(t, headerMap)
}

func TestHeaderMapFromMetadataWithAllowlist(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "SomeInformation",
		"InjectedHeader", "ShouldBeDropped",
		"testheader2", "ContentsOfTestHeader2", // case-insensitive match
	)

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1", "TestHeader2")

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, "SomeInformation", headerMap["TestHeader1"])
	require.Equal(t, "ContentsOfTestHeader2", headerMap["testheader2"])
	_, present := headerMap["InjectedHeader"]
	require.False(t, present, "non-allowlisted header name must be dropped")
}

func TestHeaderMapFromMetadataAllowlistBoundsSize(t *testing.T) {
	md := metadata.New(nil)
	// 3 pairs supplied, but allowlist has only 1 entry -> the whole payload is rejected.
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "A",
		"TestHeader1", "B",
		"TestHeader1", "C",
	)

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1")

	require.Nil(t, HeaderMapFromContext(ctx), "oversized payload must be rejected")
}

func TestHeaderMapFromMetadataTruncatesValues(t *testing.T) {
	long := make([]byte, maxForwardedHeaderValueLen+100)
	for i := range long {
		long[i] = 'a'
	}
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", string(long))

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1")

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, maxForwardedHeaderValueLen, len(headerMap["TestHeader1"]))
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
		"TestHeader1":    "RequestID",
		"InjectedHeader": "ShouldBeDropped",
	}

	req := &http.Request{
		Method:     "GET",
		RequestURI: "/HTTPHeaderTest",
		Body:       http.NoBody,
		Header:     http.Header{},
	}
	InjectHeadersIntoHTTPRequest(contentsMap, req, "TestHeader1")

	require.Equal(t, "RequestID", req.Header.Get("TestHeader1"))
	require.Empty(t, req.Header.Get("InjectedHeader"))
}
