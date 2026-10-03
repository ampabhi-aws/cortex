package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientConfig_IsConfigured(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  ClientConfig
		want bool
	}{
		{name: "empty", cfg: ClientConfig{}, want: false},
		{name: "cert", cfg: ClientConfig{CertPath: "cert.pem"}, want: true},
		{name: "key", cfg: ClientConfig{KeyPath: "key.pem"}, want: true},
		{name: "ca", cfg: ClientConfig{CAPath: "ca.pem"}, want: true},
		{name: "server_name", cfg: ClientConfig{ServerName: "svc"}, want: true},
		{name: "insecure_skip_verify", cfg: ClientConfig{InsecureSkipVerify: true}, want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.cfg.IsConfigured())
		})
	}

	var nilCfg *ClientConfig
	assert.False(t, nilCfg.IsConfigured())
}

func TestClientConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("enabled with populated fields passes", func(t *testing.T) {
		c := &ClientConfig{CertPath: "cert.pem", KeyPath: "key.pem", CAPath: "ca.pem"}
		require.NoError(t, c.Validate(true))
	})

	t.Run("disabled with no fields passes", func(t *testing.T) {
		c := &ClientConfig{}
		require.NoError(t, c.Validate(false))
	})

	t.Run("disabled with cert_path fails", func(t *testing.T) {
		c := &ClientConfig{CertPath: "cert.pem"}
		err := c.Validate(false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTLSFieldsSetButDisabled)
	})

	t.Run("disabled with ca_path fails", func(t *testing.T) {
		c := &ClientConfig{CAPath: "ca.pem"}
		err := c.Validate(false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTLSFieldsSetButDisabled)
	})

	t.Run("disabled with insecure_skip_verify fails", func(t *testing.T) {
		c := &ClientConfig{InsecureSkipVerify: true}
		err := c.Validate(false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTLSFieldsSetButDisabled)
	})

	t.Run("disabled with server_name fails", func(t *testing.T) {
		c := &ClientConfig{ServerName: "svc"}
		err := c.Validate(false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTLSFieldsSetButDisabled)
	})
}

func TestGetGRPCDialOptions_FailClosedWhenDisabledWithPopulatedTLS(t *testing.T) {
	t.Parallel()

	// Disabled + populated: must refuse rather than silently fall back to insecure.NewCredentials().
	c := &ClientConfig{CertPath: "cert.pem", KeyPath: "key.pem"}
	_, err := c.GetGRPCDialOptions(false)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTLSFieldsSetButDisabled)

	// Disabled + empty: insecure fallback is still available (opt-in cleartext).
	c = &ClientConfig{}
	opts, err := c.GetGRPCDialOptions(false)
	require.NoError(t, err)
	require.Len(t, opts, 1)
}
