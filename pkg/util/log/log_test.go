package log

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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

func TestHeaderMapFromMetadataAllowListFiltersUnknownKeys(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "SomeInformation",
		"NotAllowed", "Attacker",
		"org_id", "victim-tenant",
	)

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"TestHeader1"})

	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Equal(t, map[string]string{"TestHeader1": "SomeInformation"}, headerMap)
}

func TestHeaderMapFromMetadataEmptyAllowListDropsEverything(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "a", "b", "c", "d")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, nil)
	require.Nil(t, HeaderMapFromContext(ctx))
}

func TestHeaderMapFromMetadataCapsPairsAndValueLength(t *testing.T) {
	md := metadata.New(nil)
	allowed := make([]string, 0, maxPropagatedHeaderPairs+5)
	for i := 0; i < maxPropagatedHeaderPairs+5; i++ {
		name := fmt.Sprintf("h%d", i)
		allowed = append(allowed, name)
		md.Append(HeaderPropagationStringForRequestLogging, name, strings.Repeat("x", maxPropagatedHeaderValueLen+100))
	}

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, allowed)
	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.LessOrEqual(t, len(headerMap), maxPropagatedHeaderPairs)
	for _, v := range headerMap {
		require.LessOrEqual(t, len(v), maxPropagatedHeaderValueLen)
	}
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
