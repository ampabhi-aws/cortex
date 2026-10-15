package cortex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigSerializationRedactsSecrets is a regression test for the
// vulnerability where several credential fields were plain Go strings
// and therefore printed verbatim by GET /config.
//
// It constructs a cortex.Config, populates every known credential-bearing
// field with a unique sentinel value, YAML-marshals the whole structure
// (as the /config endpoint does) and asserts no sentinel is present in
// the output.
func TestConfigSerializationRedactsSecrets(t *testing.T) {
	const (
		swiftPassword     = "SENTINEL-SWIFT-PASSWORD-DO-NOT-LEAK"
		etcdPassword      = "SENTINEL-ETCD-PASSWORD-DO-NOT-LEAK"
		amBasicAuthPass   = "SENTINEL-AM-BASICAUTH-PASSWORD-DO-NOT-LEAK"
		amURLUserPassword = "SENTINEL-AM-URL-PASSWORD-DO-NOT-LEAK"
		dbURLUserPassword = "SENTINEL-DB-URL-PASSWORD-DO-NOT-LEAK"
	)

	// Start from the shipped defaults.
	cfg := newDefaultConfig()

	// Swift object store password - plumbed into every Bucket.Config consumer.
	cfg.BlocksStorage.Bucket.Swift.Password.Value = swiftPassword
	cfg.RulerStorage.Swift.Password.Value = swiftPassword
	cfg.AlertmanagerStorage.Swift.Password.Value = swiftPassword

	// etcd ring KV password - every ring embeds kv.StoreConfig, so we touch
	// a representative subset covering all affected top-level sections.
	cfg.Distributor.DistributorRing.KVStore.Etcd.Password.Value = etcdPassword
	cfg.Distributor.HATrackerConfig.KVStore.Etcd.Password.Value = etcdPassword
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password.Value = etcdPassword
	cfg.Ruler.Ring.KVStore.Etcd.Password.Value = etcdPassword
	cfg.Compactor.ShardingRing.KVStore.Etcd.Password.Value = etcdPassword
	cfg.StoreGateway.ShardingRing.KVStore.Etcd.Password.Value = etcdPassword
	cfg.Alertmanager.ShardingRing.KVStore.Etcd.Password.Value = etcdPassword

	// Ruler -> Alertmanager basic-auth password (util.BasicAuth embedded
	// into ruler.NotifierConfig).
	cfg.Ruler.Notifier.BasicAuth.Password.Value = amBasicAuthPass

	// Ruler -> Alertmanager URL with embedded user:password@ userinfo.
	cfg.Ruler.AlertmanagerURL = flagext.URLString("https://user:" + amURLUserPassword + "@am.example.com/alertmanager")

	// configs-service DSN - a URL with embedded userinfo.
	require.NoError(t, cfg.Configs.DB.URI.Set("postgres://user:"+dbURLUserPassword+"@db.example.com/configs?sslmode=disable"))

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	rendered := string(out)

	for _, sentinel := range []string{
		swiftPassword,
		etcdPassword,
		amBasicAuthPass,
		amURLUserPassword,
		dbURLUserPassword,
	} {
		require.Falsef(t, strings.Contains(rendered, sentinel),
			"configured secret %q must not appear in YAML-marshalled cortex.Config", sentinel)
	}
}
