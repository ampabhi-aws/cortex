package etcd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cortextls "github.com/cortexproject/cortex/pkg/util/tls"
)

func TestConfig_Validate(t *testing.T) {
	t.Run("empty config is valid", func(t *testing.T) {
		cfg := Config{}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("password with TLS explicitly enabled is valid", func(t *testing.T) {
		cfg := Config{
			Password:  "secret",
			EnableTLS: true,
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("password with https endpoint is valid", func(t *testing.T) {
		cfg := Config{
			Endpoints: []string{"https://etcd:2379"},
			Password:  "secret",
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("password with TLS paths is valid (TLS implied)", func(t *testing.T) {
		cfg := Config{
			Password: "secret",
			TLS: cortextls.ClientConfig{
				CAPath: "/etc/ssl/ca.pem",
			},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("password without TLS is rejected", func(t *testing.T) {
		cfg := Config{
			Endpoints: []string{"etcd:2379"},
			Password:  "secret",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEtcdPasswordWithoutTLS)
	})

	t.Run("username only without password does not require TLS", func(t *testing.T) {
		// Username on its own does not carry a credential; this is still allowed
		// so pre-existing deployments that supply only a username (unusual) do
		// not break. The sensitive check is on Password.
		cfg := Config{
			UserName: "someuser",
		}
		assert.NoError(t, cfg.Validate())
	})
}

func TestConfig_GetTLS_ImpliedByPaths(t *testing.T) {
	// When any TLS path is configured, GetTLS must build a TLS config even if
	// EnableTLS is left at its default; otherwise the operator-supplied TLS
	// material would be silently discarded.
	cfg := Config{
		TLS: cortextls.ClientConfig{
			ServerName: "etcd.local",
		},
	}
	tlsCfg, err := cfg.GetTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	assert.Equal(t, "etcd.local", tlsCfg.ServerName)
}

func TestConfig_GetTLS_ImpliedByHTTPSEndpoint(t *testing.T) {
	cfg := Config{
		Endpoints: []string{"https://etcd:2379"},
	}
	tlsCfg, err := cfg.GetTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
}

func TestConfig_GetTLS_DisabledByDefault(t *testing.T) {
	cfg := Config{
		Endpoints: []string{"etcd:2379"},
	}
	tlsCfg, err := cfg.GetTLS()
	require.NoError(t, err)
	assert.Nil(t, tlsCfg)
}
