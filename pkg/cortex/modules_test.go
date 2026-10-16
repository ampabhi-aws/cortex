package cortex

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	prom_storage "github.com/prometheus/prometheus/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/server"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

func changeTargetConfig(c *Config) {
	c.Target = []string{"all", "ruler"}
}

func TestAPIConfig(t *testing.T) {
	actualCfg := newDefaultConfig()

	cortex := &Cortex{
		Server: &server.Server{},
	}

	for _, tc := range []struct {
		name               string
		path               string
		actualCfg          func(*Config)
		expectedStatusCode int
		expectedBody       func(*testing.T, string)
	}{
		{
			name:               "running with default config",
			path:               "/config",
			expectedStatusCode: 200,
		},
		{
			name:               "defaults with default config",
			path:               "/config?mode=defaults",
			expectedStatusCode: 200,
		},
		{
			name:               "diff with default config",
			path:               "/config?mode=diff",
			expectedStatusCode: 200,
			expectedBody: func(t *testing.T, body string) {
				assert.Equal(t, "{}\n", body)
			},
		},
		{
			name:               "running with changed target config",
			path:               "/config",
			actualCfg:          changeTargetConfig,
			expectedStatusCode: 200,
			expectedBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "target: all,ruler\n")
			},
		},
		{
			name:               "defaults with changed target config",
			path:               "/config?mode=defaults",
			actualCfg:          changeTargetConfig,
			expectedStatusCode: 200,
			expectedBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "target: all\n")
			},
		},
		{
			name:               "diff with changed target config",
			path:               "/config?mode=diff",
			actualCfg:          changeTargetConfig,
			expectedStatusCode: 200,
			expectedBody: func(t *testing.T, body string) {
				assert.Equal(t, "target: all,ruler\n", body)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cortex.Server.HTTP = mux.NewRouter()

			cortex.Cfg = *actualCfg
			if tc.actualCfg != nil {
				tc.actualCfg(&cortex.Cfg)
			}

			_, err := cortex.initAPI()
			require.NoError(t, err)

			req := httptest.NewRequest("GET", tc.path, nil)
			resp := httptest.NewRecorder()

			cortex.Server.HTTP.ServeHTTP(resp, req)

			assert.Equal(t, tc.expectedStatusCode, resp.Code)

			if tc.expectedBody != nil {
				tc.expectedBody(t, resp.Body.String())
			}
		})
	}
}

func TestCortex_InitRulerStorage(t *testing.T) {
	tests := map[string]struct {
		config       *Config
		expectedInit bool
	}{
		"should init the ruler storage with target=ruler": {
			config: func() *Config {
				cfg := newDefaultConfig()
				cfg.Target = []string{"ruler"}
				cfg.RulerStorage.Backend = "local"
				cfg.RulerStorage.Local.Directory = os.TempDir()
				return cfg
			}(),
			expectedInit: true,
		},
		"should not init the ruler storage on default config with target=all": {
			config: func() *Config {
				cfg := newDefaultConfig()
				cfg.Target = []string{"all"}
				return cfg
			}(),
			expectedInit: false,
		},
		"should init the ruler storage on ruler storage config with target=all": {
			config: func() *Config {
				cfg := newDefaultConfig()
				cfg.Target = []string{"all"}
				cfg.RulerStorage.Backend = "local"
				cfg.RulerStorage.Local.Directory = os.TempDir()
				return cfg
			}(),
			expectedInit: true,
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			cortex := &Cortex{
				Server: &server.Server{},
				Cfg:    *testData.config,
			}

			_, err := cortex.initRulerStorage()
			require.NoError(t, err)

			if testData.expectedInit {
				assert.NotNil(t, cortex.RulerStorage)
			} else {
				assert.Nil(t, cortex.RulerStorage)
			}
		})
	}
}

type myPusher struct{}

func (p *myPusher) Push(ctx context.Context, req *cortexpb.WriteRequest) (*cortexpb.WriteResponse, error) {
	return nil, nil
}

type myQueryable struct{}

func (q *myQueryable) Querier(ctx context.Context, mint, maxt int64) (prom_storage.Querier, error) {
	return prom_storage.NoopQuerier(), nil
}

func Test_setupModuleManager(t *testing.T) {
	tests := []struct {
		config           *Config
		expectedOriginal bool
	}{
		{
			config: func() *Config {
				cfg := newDefaultConfig()
				cfg.Target = []string{"all"}
				cfg.RulerStorage.Backend = "local"
				cfg.RulerStorage.Local.Directory = os.TempDir()
				cfg.ExternalPusher = &myPusher{}
				cfg.ExternalQueryable = &myQueryable{}
				return cfg
			}(),
			expectedOriginal: false,
		},
		{
			config: func() *Config {
				cfg := newDefaultConfig()
				cfg.Target = []string{"all"}
				cfg.RulerStorage.Backend = "local"
				cfg.RulerStorage.Local.Directory = os.TempDir()
				return cfg
			}(),
			expectedOriginal: true,
		},
	}

	for _, test := range tests {
		cortex := &Cortex{
			Cfg:    *test.config,
			Server: &server.Server{},
		}

		err := cortex.setupModuleManager()
		require.Nil(t, err)

		deps := cortex.ModuleManager.DependenciesForModule(Ruler)
		originalDependecies := []string{DistributorService, StoreQueryable}

		if test.expectedOriginal {
			check := []bool{false, false}
			for _, dep := range deps {
				for i, o := range originalDependecies {
					if dep == o {
						check[i] = true
					}
				}
			}
			for _, val := range check {
				require.True(t, val)
			}
		} else {
			for _, dep := range deps {
				for _, o := range originalDependecies {
					require.NotEqual(t, dep, o)
				}
			}
		}
	}
}

// TestConfigYAMLSecretsRedacted verifies that credential-bearing fields are
// masked by yaml.Marshal (as served by GET /config). Any secret flag added to
// the config must use flagext.Secret so its MarshalYAML emits "********"
// rather than the plaintext value.
func TestConfigYAMLSecretsRedacted(t *testing.T) {
	const (
		swiftPwd        = "swift-plain-text-password"
		etcdPwd         = "etcd-plain-text-password"
		basicAuthPwd    = "ruler-am-plain-text-password"
		configsURI      = "postgres://user:configs-uri-plain-text-password@db/configs"
		configsPwdFile  = "/etc/configs/db-password-file"
	)

	cfg := newDefaultConfig()
	// Blocks storage uses bucket.Config, which embeds swift.Config.
	cfg.BlocksStorage.Bucket.Swift.Password = flagext.Secret{Value: swiftPwd}
	// The ingester ring uses kv.Config, which embeds etcd.Config.
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password = flagext.Secret{Value: etcdPwd}
	// Ruler Alertmanager notifier basic auth, via util.BasicAuth.
	cfg.Ruler.Notifier.BasicAuth.Password = flagext.Secret{Value: basicAuthPwd}
	// Configs database DSN and password file.
	cfg.Configs.DB.URI = flagext.Secret{Value: configsURI}
	cfg.Configs.DB.PasswordFile = flagext.Secret{Value: configsPwdFile}

	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	body := string(out)

	for _, plaintext := range []string{swiftPwd, etcdPwd, basicAuthPwd, configsURI, configsPwdFile} {
		assert.NotContainsf(t, body, plaintext, "plaintext secret leaked in marshalled config: %q", plaintext)
	}
	// Must see the masked marker at least once.
	assert.True(t, strings.Contains(body, "********"), "expected redacted marker in marshalled config")
}
