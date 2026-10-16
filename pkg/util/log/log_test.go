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

	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"TestHeader1", "TestHeader2"})

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

func TestHeaderMapFromMetadataAllowListFilters(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "SomeInformation",
		"TestHeader2", "ContentsOfTestHeader2",
		"X-Injected", "attacker",
		"org_id", "forged")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"TestHeader1"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, 1, len(headerMap))
	require.Equal(t, "SomeInformation", headerMap["TestHeader1"])
	require.NotContains(t, headerMap, "X-Injected")
	require.NotContains(t, headerMap, "org_id")
	require.NotContains(t, headerMap, "TestHeader2")
}

func TestHeaderMapFromMetadataAllowListIsCaseInsensitive(t *testing.T) {
	md := metadata.New(nil)
	// Client sends the key with different casing than the operator configured.
	md.Append(HeaderPropagationStringForRequestLogging, "x-request-id", "abc123")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"X-Request-ID"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, 1, len(headerMap))
	// Stored under the operator-configured casing, to match the HTTP path.
	require.Equal(t, "abc123", headerMap["X-Request-ID"])
}

func TestHeaderMapFromMetadataRejectsInvalidTokenKeys(t *testing.T) {
	md := metadata.New(nil)
	// Key contains a space, which is not a valid HTTP token character.
	md.Append(HeaderPropagationStringForRequestLogging, "Bad Header", "value")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"Bad Header"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, 0, len(headerMap))
}

func TestHeaderMapFromMetadataTruncatesLongValues(t *testing.T) {
	long := make([]byte, maxForwardedHeaderValueLen+128)
	for i := range long {
		long[i] = 'a'
	}
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader", string(long))

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, []string{"TestHeader"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, maxForwardedHeaderValueLen, len(headerMap["TestHeader"]))
}

func TestHeaderMapFromMetadataNoAllowListMeansNoHeaders(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation")

	ctx := context.Background()
	ctx = ContextWithHeaderMapFromMetadata(ctx, md, nil)

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, 0, len(headerMap))
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
