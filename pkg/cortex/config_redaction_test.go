package cortex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestConfigRedaction is a regression test for the /config information
// disclosure finding. It seeds every credential field reachable via the live
// cortex.Config with a sentinel value, marshals the config to YAML (the same
// path /config uses) and asserts that no sentinel survives the marshal.
func TestConfigRedaction(t *testing.T) {
	cfg := newDefaultConfig()

	swiftBlocks := "sentinel-swift-blocks"
	swiftRuler := "sentinel-swift-ruler"
	swiftAM := "sentinel-swift-am"
	etcdRing := "sentinel-etcd-ring"
	etcdRuler := "sentinel-etcd-ruler"
	etcdAM := "sentinel-etcd-am"
	rulerAMBasicAuth := "sentinel-ruler-am-basicauth"
	configsDBURIPassword := "sentinel-configs-db"

	require.NoError(t, cfg.BlocksStorage.Bucket.Swift.Password.Set(swiftBlocks))
	require.NoError(t, cfg.RulerStorage.Swift.Password.Set(swiftRuler))
	require.NoError(t, cfg.AlertmanagerStorage.Swift.Password.Set(swiftAM))

	require.NoError(t, cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password.Set(etcdRing))
	require.NoError(t, cfg.Ruler.Ring.KVStore.Etcd.Password.Set(etcdRuler))
	require.NoError(t, cfg.Alertmanager.ShardingRing.KVStore.Etcd.Password.Set(etcdAM))

	require.NoError(t, cfg.Ruler.Notifier.BasicAuth.Password.Set(rulerAMBasicAuth))

	cfg.Configs.DB.URI = "postgres://cortex:" + configsDBURIPassword + "@db.example.local/configs"

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	dump := string(out)

	for _, s := range []string{
		swiftBlocks, swiftRuler, swiftAM,
		etcdRing, etcdRuler, etcdAM,
		rulerAMBasicAuth, configsDBURIPassword,
	} {
		require.NotContains(t, dump, s,
			"cleartext credential %q appeared in the marshalled config", s)
	}

	// The configs DB URI must be present but with its password component redacted.
	require.Contains(t, dump, "postgres://cortex:********@db.example.local/configs")
	// Sanity: the mask token is present in the output somewhere.
	require.True(t, strings.Contains(dump, "********"))
}
