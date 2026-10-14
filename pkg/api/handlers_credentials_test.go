package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	etcdkv "github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	swiftcfg "github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func TestSwiftAndEtcdPasswordsAreMasked(t *testing.T) {
	swiftFld, ok := reflect.TypeOf(swiftcfg.Config{}).FieldByName("Password")
	require.True(t, ok)
	require.Equal(t, reflect.TypeOf(flagext.Secret{}), swiftFld.Type)

	etcdFld, ok := reflect.TypeOf(etcdkv.Config{}).FieldByName("Password")
	require.True(t, ok)
	require.Equal(t, reflect.TypeOf(flagext.Secret{}), etcdFld.Type)
}

func TestDefaultConfigHandlerMasksSwiftPassword(t *testing.T) {
	const sentinel = "swift-sentinel-value-123"
	actual := swiftcfg.Config{
		Username: "operator",
		Password: flagext.Secret{Value: sentinel},
	}

	req := httptest.NewRequest(http.MethodGet, "http://test/config", nil)
	w := httptest.NewRecorder()
	DefaultConfigHandler(actual, swiftcfg.Config{})(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, string(body), sentinel)
	assert.Contains(t, string(body), "********")
}

func TestDefaultConfigHandlerMasksEtcdPassword(t *testing.T) {
	const sentinel = "etcd-sentinel-value-123"
	actual := etcdkv.Config{
		UserName: "operator",
		Password: flagext.Secret{Value: sentinel},
	}

	req := httptest.NewRequest(http.MethodGet, "http://test/config", nil)
	w := httptest.NewRecorder()
	DefaultConfigHandler(actual, etcdkv.Config{})(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, string(body), sentinel)
	assert.Contains(t, string(body), "********")
}
