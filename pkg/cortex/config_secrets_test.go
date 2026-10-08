package cortex

import (
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// TestConfigYAMLDoesNotLeakSecrets is a regression test for the
// "Unauthenticated GET /config leaks cleartext credentials" issue.
//
// GET /config YAML-marshals the live cortex.Config. The only redaction
// mechanism in the codebase is flagext.Secret.MarshalYAML, so every
// credential field that lands in the config must either be typed
// flagext.Secret or be redacted by a dedicated MarshalYAML method
// (see pkg/configs/db/db.go). This test seeds every known credential
// field with a unique canary value, marshals the config, and asserts
// no canary leaks into the output. Adding a new plain-string credential
// field in the future will cause this test to fail until that field is
// either converted to flagext.Secret or masked explicitly.
func TestConfigYAMLDoesNotLeakSecrets(t *testing.T) {
	cfg := &Config{}
	// Register flags so defaults are populated, mirroring the live
	// cortex.Config that /config serves.
	fs := flag.NewFlagSet("test", flag.PanicOnError)
	cfg.RegisterFlags(fs)

	type canary struct {
		name  string
		value string
		setFn func(c *Config, v string)
	}

	canaries := []canary{
		{
			name:  "blocks-storage-swift-password",
			value: "CANARY-BLOCKS-SWIFT-PW",
			setFn: func(c *Config, v string) { c.BlocksStorage.Bucket.Swift.Password.Set(v) },
		},
		{
			name:  "ruler-storage-swift-password",
			value: "CANARY-RULER-SWIFT-PW",
			setFn: func(c *Config, v string) { c.RulerStorage.Swift.Password.Set(v) },
		},
		{
			name:  "alertmanager-storage-swift-password",
			value: "CANARY-AM-SWIFT-PW",
			setFn: func(c *Config, v string) { c.AlertmanagerStorage.Swift.Password.Set(v) },
		},
		{
			name:  "blocks-storage-s3-secret-access-key",
			value: "CANARY-S3-KEY",
			setFn: func(c *Config, v string) { c.BlocksStorage.Bucket.S3.SecretAccessKey.Set(v) },
		},
		{
			name:  "blocks-storage-azure-account-key",
			value: "CANARY-AZURE-KEY",
			setFn: func(c *Config, v string) { c.BlocksStorage.Bucket.Azure.StorageAccountKey.Set(v) },
		},
		{
			name:  "ingester-ring-etcd-password",
			value: "CANARY-ETCD-INGESTER-PW",
			setFn: func(c *Config, v string) { c.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password.Set(v) },
		},
		{
			name:  "distributor-ring-etcd-password",
			value: "CANARY-ETCD-DISTRIBUTOR-PW",
			setFn: func(c *Config, v string) { c.Distributor.DistributorRing.KVStore.Etcd.Password.Set(v) },
		},
		{
			name:  "distributor-ha-tracker-etcd-password",
			value: "CANARY-ETCD-HATRACKER-PW",
			setFn: func(c *Config, v string) { c.Distributor.HATrackerConfig.KVStore.Etcd.Password.Set(v) },
		},
		{
			name:  "ingester-ring-consul-acl-token",
			value: "CANARY-CONSUL-TOKEN",
			setFn: func(c *Config, v string) { c.Ingester.LifecyclerConfig.RingConfig.KVStore.Consul.ACLToken.Set(v) },
		},
		{
			name:  "ruler-alertmanager-client-basic-auth-password",
			value: "CANARY-AM-BASIC-AUTH-PW",
			setFn: func(c *Config, v string) { c.Ruler.Notifier.BasicAuth.Password.Set(v) },
		},
		{
			name:  "configs-database-uri-password",
			value: "CANARY-CONFIGS-DB-PW",
			setFn: func(c *Config, v string) {
				c.Configs.DB.URI = "postgres://user:" + v + "@configs-db.example.com/configs?sslmode=disable"
			},
		},
	}

	for _, c := range canaries {
		c.setFn(cfg, c.value)
	}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	rendered := string(out)

	for _, c := range canaries {
		if strings.Contains(rendered, c.value) {
			t.Errorf("credential canary %q (value %q) leaked into marshalled config; "+
				"the corresponding field must be typed flagext.Secret or masked by a MarshalYAML method",
				c.name, c.value)
		}
	}
}
