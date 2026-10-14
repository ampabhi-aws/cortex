package cortex

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	prom_storage "github.com/prometheus/prometheus/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/server"

	"github.com/cortexproject/cortex/pkg/cortexpb"
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

// TestAPIConfig_MasksCredentials is a regression test for the plaintext
// credential disclosure through the /config endpoint. It configures a set of
// non-default credential-bearing fields (Swift/etcd password, ruler basic auth
// and Alertmanager URL, configs database DSN, S3 access key id) and asserts
// that none of the configured credential values appear in the marshalled
// response of /config, /config?mode=diff or /config?mode=defaults.
func TestAPIConfig_MasksCredentials(t *testing.T) {
	const (
		swiftSecret   = "swift-super-secret-password"
		etcdSecret    = "etcd-ring-password"
		basicSecret   = "alertmanager-basic-auth-password"
		amURLSecret   = "am-url-embedded-password"
		dbURISecret   = "configs-db-password"
		s3AccessKeyID = "AKIAEXAMPLEACCESSKEY"
		s3SecretKey   = "super-secret-s3-key"
	)

	cfg := newDefaultConfig()
	cfg.BlocksStorage.Bucket.Swift.Password.Value = swiftSecret
	cfg.BlocksStorage.Bucket.S3.AccessKeyID.Value = s3AccessKeyID
	cfg.BlocksStorage.Bucket.S3.SecretAccessKey.Value = s3SecretKey
	cfg.Ingester.LifecyclerConfig.RingConfig.KVStore.Etcd.Password.Value = etcdSecret
	cfg.Ruler.AlertmanagerURL = "http://amuser:" + amURLSecret + "@alertmanager/"
	cfg.Ruler.Notifier.BasicAuth.Username = "amuser"
	cfg.Ruler.Notifier.BasicAuth.Password.Value = basicSecret
	cfg.Configs.DB.URI = "postgres://dbuser:" + dbURISecret + "@db/configs"

	cortex := &Cortex{
		Cfg:    *cfg,
		Server: &server.Server{},
	}
	cortex.Server.HTTP = mux.NewRouter()

	_, err := cortex.initAPI()
	require.NoError(t, err)

	secrets := []string{swiftSecret, etcdSecret, basicSecret, amURLSecret, dbURISecret, s3AccessKeyID, s3SecretKey}

	for _, path := range []string{"/config", "/config?mode=diff", "/config?mode=defaults"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			resp := httptest.NewRecorder()
			cortex.Server.HTTP.ServeHTTP(resp, req)
			assert.Equal(t, 200, resp.Code)
			body := resp.Body.String()
			for _, s := range secrets {
				assert.NotContainsf(t, body, s, "/config response leaked credential %q at path %q", s, path)
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
