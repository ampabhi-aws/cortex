package cortex

import (
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/ring/kv/etcd"
	"github.com/cortexproject/cortex/pkg/ruler"
	"github.com/cortexproject/cortex/pkg/storage/bucket/s3"
	"github.com/cortexproject/cortex/pkg/storage/bucket/swift"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigMarshal_RedactsCredentialBearingFields seeds every credential
// bearing config field with a recognisable sentinel, marshals the whole
// top-level Cortex Config to YAML (as served by /config), and asserts that no
// sentinel ever appears verbatim. This guards against regressions where a new
// credential field is added as a plain string instead of a masking type.
func TestConfigMarshal_RedactsCredentialBearingFields(t *testing.T) {
	cfg := &Config{}
	defaultFS := flag.NewFlagSet("", flag.PanicOnError)
	cfg.RegisterFlags(defaultFS)

	const sentinel = "SUPERSECRET_SENTINEL_VALUE"
	cfg.BlocksStorage.Bucket.Swift.Password = flagext.Secret{Value: sentinel}
	cfg.RulerStorage.Swift.Password = flagext.Secret{Value: sentinel}
	cfg.AlertmanagerStorage.Swift.Password = flagext.Secret{Value: sentinel}
	cfg.BlocksStorage.Bucket.S3.AccessKeyID = flagext.Secret{Value: sentinel}
	cfg.BlocksStorage.Bucket.S3.SecretAccessKey = flagext.Secret{Value: sentinel}
	cfg.Ruler.Notifier.BasicAuth.Password = flagext.Secret{Value: sentinel}
	cfg.Ruler.AlertmanagerURL = flagext.MaskedURLStringList{Value: "http://user:" + sentinel + "@am-0/alertmanager,http://user:" + sentinel + "@am-1/alertmanager"}
	cfg.Configs.DB.URI = flagext.MaskedURLString{Value: "postgres://configs:" + sentinel + "@configs-db/configs?sslmode=disable"}
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password = flagext.Secret{Value: sentinel}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	if strings.Contains(string(out), sentinel) {
		t.Fatalf("a credential-bearing field leaked unredacted through yaml.Marshal; add a MarshalYAML masking type to the new field. Full output:\n%s", string(out))
	}

	// Also sanity-check the individual sub-configs mask by themselves, so this
	// test keeps catching regressions even if upstream reshuffles nesting.
	t.Run("BasicAuth", func(t *testing.T) {
		b := util.BasicAuth{Username: "u", Password: flagext.Secret{Value: sentinel}}
		y, err := yaml.Marshal(b)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
	t.Run("Swift", func(t *testing.T) {
		s := swift.Config{Password: flagext.Secret{Value: sentinel}}
		y, err := yaml.Marshal(s)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
	t.Run("Etcd", func(t *testing.T) {
		e := etcd.Config{Password: flagext.Secret{Value: sentinel}}
		y, err := yaml.Marshal(e)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
	t.Run("S3", func(t *testing.T) {
		s := s3.Config{AccessKeyID: flagext.Secret{Value: sentinel}, SecretAccessKey: flagext.Secret{Value: sentinel}}
		y, err := yaml.Marshal(s)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
	t.Run("ConfigsDB", func(t *testing.T) {
		c := db.Config{URI: flagext.MaskedURLString{Value: "postgres://u:" + sentinel + "@h/d"}}
		y, err := yaml.Marshal(c)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
	t.Run("RulerAlertmanagerURL", func(t *testing.T) {
		r := ruler.Config{AlertmanagerURL: flagext.MaskedURLStringList{Value: "http://u:" + sentinel + "@h/am"}}
		y, err := yaml.Marshal(r)
		require.NoError(t, err)
		require.NotContains(t, string(y), sentinel)
	})
}
