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

func TestHeaderMapFromMetadataDropsUnexpectedKeys(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"TestHeader1", "ok",
		"level", "debug",
		"caller", "evil.go:1",
		"attacker_note", "injected",
	)

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"TestHeader1"})
	headerMap := HeaderMapFromContext(ctx)

	require.NotNil(t, headerMap)
	require.Equal(t, map[string]string{"TestHeader1": "ok"}, headerMap)
}

func TestHeaderMapFromMetadataNoAllowlistIsDropped(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, nil)
	require.Nil(t, HeaderMapFromContext(ctx))
}

func TestHeaderMapFromMetadataTooManyPairs(t *testing.T) {
	md := metadata.New(nil)
	allowed := []string{}
	for i := 0; i < 100; i++ {
		k := fmt.Sprintf("k%d", i)
		md.Append(HeaderPropagationStringForRequestLogging, k, "v")
		allowed = append(allowed, k)
	}

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, allowed)
	// Over the cap -> the whole map is rejected.
	require.Nil(t, HeaderMapFromContext(ctx))
}

func TestHeaderMapFromMetadataTruncatesValues(t *testing.T) {
	longVal := strings.Repeat("a", 1024)
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", longVal)

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"TestHeader1"})
	headerMap := HeaderMapFromContext(ctx)
	require.NotNil(t, headerMap)
	require.Len(t, headerMap["TestHeader1"], 256)
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
