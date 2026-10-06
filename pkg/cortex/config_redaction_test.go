package cortex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// TestConfigRedactsCredentialFields ensures that the credential fields which
// are reachable from the live Cortex config and that would otherwise be
// emitted by GET /config are self-redacting (via flagext.Secret or an
// equivalent type that strips sensitive content from MarshalYAML output).
//
// This is a regression test for CWE-497: Exposure of Sensitive System
// Information. If a new plain-string credential field is added, it should
// either be typed as flagext.Secret or wrapped in a type whose MarshalYAML
// does not emit the raw secret.
func TestConfigRedactsCredentialFields(t *testing.T) {
	const sentinel = "CONTINUUM-SECRET-SENTINEL"

	cfg := newDefaultConfig()

	// Populate every known credential field with a sentinel.
	cfg.RulerStorage.Swift.Password = flagext.Secret{Value: sentinel}
	cfg.BlocksStorage.Bucket.Swift.Password = flagext.Secret{Value: sentinel}
	cfg.AlertmanagerStorage.Swift.Password = flagext.Secret{Value: sentinel}

	cfg.Distributor.DistributorRing.KVStore.Etcd.UserName = "redacted-user"
	cfg.Distributor.DistributorRing.KVStore.Etcd.Password = flagext.Secret{Value: sentinel}
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password = flagext.Secret{Value: sentinel}

	cfg.Ruler.Notifier.BasicAuth.Password = flagext.Secret{Value: sentinel}

	cfg.Configs.DB.URI = db.URI{Value: "postgres://user:" + sentinel + "@example.invalid/configs"}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	if strings.Contains(string(out), sentinel) {
		// Produce a helpful excerpt around the first offending occurrence.
		idx := strings.Index(string(out), sentinel)
		start := idx - 80
		if start < 0 {
			start = 0
		}
		end := idx + 160
		if end > len(out) {
			end = len(out)
		}
		t.Fatalf("sensitive sentinel leaked in YAML config dump: ...%s...", string(out[start:end]))
	}
}

// TestDBURIStripsUserinfo exercises the configs DB URI type directly.
func TestDBURIStripsUserinfo(t *testing.T) {
	u := db.URI{Value: "postgres://user:supersecret@db.example.invalid/configs?sslmode=disable"}
	out, err := yaml.Marshal(u)
	require.NoError(t, err)
	require.NotContains(t, string(out), "supersecret", "DB URI must not emit inline password")
	require.NotContains(t, string(out), "user:supersecret", "DB URI must not emit inline userinfo")
}
