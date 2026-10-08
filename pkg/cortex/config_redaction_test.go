package cortex

import (
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	"github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigRedaction is a regression test for the "Unauthenticated GET
// /config discloses full running config with cleartext credentials" finding.
// It populates every credential field that was previously typed as a plain
// string, marshals to YAML as /config does, and asserts no sentinel value
// survives marshalling.
func TestConfigRedaction(t *testing.T) {
	type bundle struct {
		Swift   swift.Config   `yaml:"swift"`
		Etcd    etcd.Config    `yaml:"etcd"`
		Auth    util.BasicAuth `yaml:",inline"`
		Configs db.Config      `yaml:"configs_db"`
	}

	b := bundle{
		Swift: swift.Config{
			Username: "cortex",
			Password: flagext.Secret{Value: "SENTINEL-SWIFT-1"},
		},
		Etcd: etcd.Config{
			Endpoints: []string{"localhost:2379"},
			UserName:  "root",
			Password:  flagext.Secret{Value: "SENTINEL-ETCD-2"},
		},
		Auth: util.BasicAuth{
			Username: "ruler",
			Password: flagext.Secret{Value: "SENTINEL-AM-3"},
		},
		Configs: db.Config{
			URI: "postgres://cfguser:SENTINEL-PG-4@configs-db/configs?sslmode=disable",
		},
	}

	out, err := yaml.Marshal(b)
	require.NoError(t, err)
	rendered := string(out)

	sentinels := []string{
		"SENTINEL-SWIFT-1",
		"SENTINEL-ETCD-2",
		"SENTINEL-AM-3",
		"SENTINEL-PG-4",
	}
	for _, s := range sentinels {
		require.NotContains(t, rendered, s, "sensitive value leaked into YAML output: %s", rendered)
	}

	// flagext.Secret should emit the masking string, and the configs DB URI
	// password should be rewritten to xxxxx by Config.MarshalYAML.
	require.Contains(t, rendered, "********", "flagext.Secret mask should appear in output: %s", rendered)
	require.Contains(t, rendered, "xxxxx", "configs DB URI password should be masked: %s", rendered)
}
