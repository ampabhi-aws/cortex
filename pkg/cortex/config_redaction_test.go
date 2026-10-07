package cortex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func TestConfigRedactsCredentialCanaries(t *testing.T) {
	const (
		canarySwiftPassword     = "CANARY-SWIFT-PASSWORD"
		canaryEtcdPassword      = "CANARY-ETCD-PASSWORD"
		canaryBasicAuthPassword = "CANARY-BASIC-AUTH-PASSWORD"
		canaryConfigsDBPassword = "CANARY-CONFIGS-DB-PASSWORD"
		canaryS3SecretAccessKey = "CANARY-S3-SECRET-ACCESS-KEY"
		canaryAzureAccountKey   = "CANARY-AZURE-ACCOUNT-KEY"
		canaryGCSServiceAccount = "CANARY-GCS-SERVICE-ACCOUNT"
		canaryConsulACLToken    = "CANARY-CONSUL-ACL-TOKEN"
	)

	cfg := newDefaultConfig()

	cfg.BlocksStorage.Bucket.Swift.Password = flagext.Secret{Value: canarySwiftPassword}
	cfg.BlocksStorage.Bucket.S3.SecretAccessKey = flagext.Secret{Value: canaryS3SecretAccessKey}
	cfg.BlocksStorage.Bucket.Azure.StorageAccountKey = flagext.Secret{Value: canaryAzureAccountKey}
	cfg.BlocksStorage.Bucket.GCS.ServiceAccount = flagext.Secret{Value: canaryGCSServiceAccount}

	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password = flagext.Secret{Value: canaryEtcdPassword}
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Consul.ACLToken = flagext.Secret{Value: canaryConsulACLToken}

	cfg.Ruler.Notifier.BasicAuth.Password = flagext.Secret{Value: canaryBasicAuthPassword}

	cfg.Configs.DB.URI = "postgres://configs:" + canaryConfigsDBPassword + "@configs-db.weave.local/configs?sslmode=disable"

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	rendered := string(out)

	for _, canary := range []string{
		canarySwiftPassword,
		canaryEtcdPassword,
		canaryBasicAuthPassword,
		canaryConfigsDBPassword,
		canaryS3SecretAccessKey,
		canaryAzureAccountKey,
		canaryGCSServiceAccount,
		canaryConsulACLToken,
	} {
		require.Falsef(t, strings.Contains(rendered, canary),
			"marshalled cortex.Config leaked credential canary (canary=%s)",
			canary)
	}

	require.Containsf(t, rendered, "********",
		"expected redaction sentinel in /config output")
}
