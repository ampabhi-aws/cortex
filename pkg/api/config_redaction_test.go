package api

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	"github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

type bundleCfg struct {
	Swift swift.Config   `yaml:"blocks_storage_swift"`
	Etcd  etcd.Config    `yaml:"etcd"`
	BA    util.BasicAuth `yaml:"alertmanager_client"`
}

func TestConfigsRedactViaYAMLMarshal(t *testing.T) {
	const canary = "canary-value"
	cfg := &bundleCfg{}
	cfg.Swift.Password = flagext.Secret{Value: canary}
	cfg.Etcd.Password = flagext.Secret{Value: canary}
	cfg.BA.Password = flagext.Secret{Value: canary}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	require.NoError(t, enc.Encode(cfg))
	require.NoError(t, enc.Close())

	assert.NotContains(t, buf.String(), canary)
	assert.Contains(t, buf.String(), "****")
}

func TestConfigHandlerRedactsBundle(t *testing.T) {
	const canary = "canary-value"
	actual := &bundleCfg{}
	actual.Swift.Password = flagext.Secret{Value: canary}
	actual.Etcd.Password = flagext.Secret{Value: canary}
	actual.BA.Password = flagext.Secret{Value: canary}

	h := DefaultConfigHandler(actual, &bundleCfg{})
	req := httptest.NewRequest("GET", "http://t/config", nil)
	w := httptest.NewRecorder()
	h(w, req)
	resp := w.Result()
	require.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), canary)
}
