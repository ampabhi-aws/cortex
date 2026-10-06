package cortex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	prom_storage "github.com/prometheus/prometheus/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/middleware"
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

// TestConfigsRoutesWrappedByAuth is a regression test for the configs module
// bypassing the Cortex HTTP auth middleware. Every tenant-scoped configs route
// MUST be registered through pkg/api.API.RegisterRoute with auth=true so that
// it inherits the configured AuthMiddleware (either fakeauth, which pins the
// tenant, or AuthenticateUser, which rejects requests without the tenant
// header). The test installs a sentinel AuthMiddleware and asserts that every
// route registered on Server.HTTP by initAPI + initConfig either flows through
// the sentinel or is listed in an explicit unauthenticated allowlist. This
// prevents future modules from silently opting out of auth by registering on
// the raw server mux.
func TestConfigsRoutesWrappedByAuth(t *testing.T) {
	// Routes we explicitly allow to be registered without auth. Any new
	// unauthenticated route must be added here and reviewed; routes NOT in
	// this list and NOT wrapped by AuthMiddleware will fail the test.
	allowlist := map[string]struct{}{
		"/":                  {},
		"/config":            {},
		"/debug/fgprof":      {},
	}

	const sentinelHeader = "X-Test-Auth-Sentinel"
	sentinel := middleware.Func(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(sentinelHeader, "yes")
			next.ServeHTTP(w, r)
		})
	})

	cfg := newDefaultConfig()
	cfg.API.HTTPAuthMiddleware = sentinel
	cfg.Configs.DB.URI = "memory://"

	cortex := &Cortex{
		Server: &server.Server{HTTP: mux.NewRouter()},
		Cfg:    *cfg,
	}

	_, err := cortex.initAPI()
	require.NoError(t, err)

	_, err = cortex.initConfig()
	require.NoError(t, err)

	// Collect every registered route path/method.
	type routeKey struct {
		path   string
		method string
	}
	var routes []routeKey
	err = cortex.Server.HTTP.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, perr := route.GetPathTemplate()
		if perr != nil {
			// Routes without an explicit path (e.g. PathPrefix) are skipped;
			// configs module does not use any.
			return nil
		}
		methods, merr := route.GetMethods()
		if merr != nil || len(methods) == 0 {
			methods = []string{http.MethodGet}
		}
		for _, m := range methods {
			routes = append(routes, routeKey{path: path, method: m})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, routes, "expected at least one route registered on Server.HTTP")

	// Deterministic order for diagnostics.
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].path == routes[j].path {
			return routes[i].method < routes[j].method
		}
		return routes[i].path < routes[j].path
	})

	// Ensure the configs routes are actually present — otherwise the test is
	// vacuously green and would miss a future regression that removes them.
	expectedConfigsRoutes := []routeKey{
		{"/api/prom/configs/alertmanager", http.MethodGet},
		{"/api/prom/configs/alertmanager", http.MethodPost},
		{"/api/prom/configs/alertmanager/validate", http.MethodPost},
		{"/api/prom/configs/deactivate", http.MethodDelete},
		{"/api/prom/configs/restore", http.MethodPost},
		{"/api/prom/configs/rules", http.MethodGet},
		{"/api/prom/configs/rules", http.MethodPost},
		{"/api/prom/configs/templates", http.MethodGet},
		{"/api/prom/configs/templates", http.MethodPost},
	}
	for _, want := range expectedConfigsRoutes {
		found := false
		for _, got := range routes {
			if got == want {
				found = true
				break
			}
		}
		assert.Truef(t, found, "expected configs route %s %s to be registered on Server.HTTP", want.method, want.path)
	}

	// For each route, dispatch a request through the Server.HTTP mux and
	// assert the sentinel middleware ran (unless the path is in the
	// allowlist). The sentinel runs before the handler, so even if the
	// handler itself errors out we still see the header.
	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(""))
		rr := httptest.NewRecorder()
		cortex.Server.HTTP.ServeHTTP(rr, req.WithContext(context.Background()))

		wrapped := rr.Header().Get(sentinelHeader) == "yes"
		_, allowed := allowlist[rt.path]
		if !wrapped && !allowed {
			t.Errorf("route %s %s is registered on Server.HTTP but is NOT wrapped by AuthMiddleware and is NOT in the unauthenticated allowlist; register it via API.RegisterRoute(..., auth=true) or add it explicitly to the allowlist with justification", rt.method, rt.path)
		}
	}
}
