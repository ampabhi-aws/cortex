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

	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1", "TestHeader2")

	headerMap := HeaderMapFromContext(ctx)

	require.Contains(t, headerMap, "TestHeader1")
	require.Contains(t, headerMap, "TestHeader2")
	require.Equal(t, "SomeInformation", headerMap["TestHeader1"])
	require.Equal(t, "ContentsOfTestHeader2", headerMap["TestHeader2"])
}

func TestHeaderMapFromMetadataFiltersUntargetedKeys(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "SomeInformation",
		"Forged", "ShouldBeDropped")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1")

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Contains(t, headerMap, "TestHeader1")
	require.NotContains(t, headerMap, "Forged")
}

func TestHeaderMapFromMetadataDropsAllWhenNoTargets(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md)

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Empty(t, headerMap)
}

func TestHeaderMapFromMetadataTruncatesLongValues(t *testing.T) {
	long := make([]byte, maxForwardedLogHeaderValueLen+500)
	for i := range long {
		long[i] = 'a'
	}
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", string(long))

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1")

	headerMap := HeaderMapFromContext(ctx)
	require.Equal(t, maxForwardedLogHeaderValueLen, len(headerMap["TestHeader1"]))
}

func TestHeaderMapFromMetadataWithImproperLength(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation", "TestHeader2", "ContentsOfTestHeader2", "Test3")

	ctx := context.Background()

	ctx = ContextWithHeaderMapFromMetadata(ctx, md, "TestHeader1", "TestHeader2", "Test3")

	headerMap := HeaderMapFromContext(ctx)
	require.Nil(t, headerMap)
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
