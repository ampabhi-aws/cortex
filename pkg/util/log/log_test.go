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

func TestHeaderMapFromMetadataEnforcesAllowlist(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"X-Scope-OrgID", "tenant-1",
		"level", "debug",
		"attacker_field", "anything",
	)

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"X-Scope-OrgID"})

	headerMap := HeaderMapFromContext(ctx)
	require.Equal(t, map[string]string{"X-Scope-OrgID": "tenant-1"}, headerMap)
}

func TestHeaderMapFromMetadataAllowlistIsCaseInsensitive(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging,
		"x-scope-orgid", "tenant-1",
	)

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, []string{"X-Scope-OrgID"})

	headerMap := HeaderMapFromContext(ctx)
	// Allowlisted names are normalised to the operator-configured spelling.
	require.Equal(t, map[string]string{"X-Scope-OrgID": "tenant-1"}, headerMap)
}

func TestHeaderMapFromMetadataEmptyAllowlistDropsEverything(t *testing.T) {
	md := metadata.New(nil)
	md.Append(HeaderPropagationStringForRequestLogging, "TestHeader1", "SomeInformation")

	ctx := ContextWithHeaderMapFromMetadata(context.Background(), md, nil)

	require.Empty(t, HeaderMapFromContext(ctx))
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
