package alertmanager

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyConfigPropagatesBuildIntegrationsError(t *testing.T) {
	user := "tenant-a"
	reg := prometheus.NewPedanticRegistry()
	am, err := New(&Config{
		UserID:          user,
		Logger:          log.NewNopLogger(),
		TenantDataDir:   t.TempDir(),
		ExternalURL:     &url.URL{Path: "/am"},
		ShardingEnabled: false,
	}, reg)
	require.NoError(t, err)
	defer am.StopAndWait()

	nonExistentCA := t.TempDir() + "/does-not-exist-ca.pem"
	badCfgRaw := "route:\n  receiver: r\nreceivers:\n- name: r\n  webhook_configs:\n  - url: http://example.invalid/h\n    http_config:\n      tls_config:\n        ca_file: " + nonExistentCA + "\n"
	badCfg, err := config.Load(badCfgRaw)
	require.NoError(t, err)

	err = am.ApplyConfig(user, badCfg, badCfgRaw)
	require.Error(t, err, "ApplyConfig must propagate buildIntegrationsMap errors")
	assert.True(t,
		strings.Contains(err.Error(), "integrations") ||
			strings.Contains(err.Error(), "does-not-exist-ca") ||
			strings.Contains(err.Error(), "ca_file") ||
			strings.Contains(err.Error(), "CA"),
		"error should mention the integrations or CA failure, got: %v", err)

	goodCfgRaw := "route:\n  receiver: r\nreceivers:\n- name: r\n  webhook_configs:\n  - url: http://example.invalid/h\n"
	goodCfg, err := config.Load(goodCfgRaw)
	require.NoError(t, err)
	require.NoError(t, am.ApplyConfig(user, goodCfg, goodCfgRaw))
	assert.NotNil(t, am.dispatcher)

	prevDispatcher := am.dispatcher
	err = am.ApplyConfig(user, badCfg, badCfgRaw)
	require.Error(t, err)
	assert.Same(t, prevDispatcher, am.dispatcher,
		"a failed ApplyConfig must preserve the previously-working dispatcher")
}
