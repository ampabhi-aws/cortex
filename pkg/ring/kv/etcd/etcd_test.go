package etcd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := map[string]struct {
		cfg     Config
		wantErr bool
	}{
		"no credentials: ok": {
			cfg:     Config{Endpoints: []string{"etcd:2379"}},
			wantErr: false,
		},
		"credentials + TLS enabled: ok": {
			cfg:     Config{Endpoints: []string{"etcd:2379"}, UserName: "u", Password: "p", EnableTLS: true},
			wantErr: false,
		},
		"credentials + https endpoint: ok": {
			cfg:     Config{Endpoints: []string{"https://etcd:2379"}, UserName: "u", Password: "p"},
			wantErr: false,
		},
		"credentials + unixs endpoint: ok": {
			cfg:     Config{Endpoints: []string{"unixs://etcd.sock"}, UserName: "u", Password: "p"},
			wantErr: false,
		},
		"credentials without TLS: error": {
			cfg:     Config{Endpoints: []string{"etcd:2379"}, UserName: "u", Password: "p"},
			wantErr: true,
		},
		"password only without TLS: error": {
			cfg:     Config{Endpoints: []string{"http://etcd:2379"}, Password: "p"},
			wantErr: true,
		},
		"username only without TLS: error": {
			cfg:     Config{Endpoints: []string{"http://etcd:2379"}, UserName: "u"},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate(nil)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_GetTLS_HTTPSEndpointForcesTLSConfig(t *testing.T) {
	cfg := Config{Endpoints: []string{"https://etcd:2379"}}
	tlsCfg, err := cfg.GetTLS()
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg, "GetTLS must return a non-nil tls.Config for https:// endpoints so the etcd client does not dial unencrypted while authenticating")
}

func TestConfig_GetTLS_PlainEndpointReturnsNil(t *testing.T) {
	cfg := Config{Endpoints: []string{"etcd:2379"}}
	tlsCfg, err := cfg.GetTLS()
	require.NoError(t, err)
	assert.Nil(t, tlsCfg)
}
