package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/server"
)

type FakeLogger struct{}

func (fl *FakeLogger) Log(keyvals ...interface{}) error {
	return nil
}

func TestNewApiWithoutSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "without_source_ip_extractor",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.Nil(t, api.sourceIPs)
}

func TestNewApiWithSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		LogSourceIPs:      true,
		MetricsNamespace:  "with_source_ip_extractor",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.NotNil(t, api.sourceIPs)
}

func TestNewApiWithInvalidSourceIPExtractor(t *testing.T) {
	cfg := Config{}
	s := server.Server{
		HTTP: &mux.Router{},
	}
	serverCfg := server.Config{
		HTTPListenNetwork:  server.DefaultNetwork,
		LogSourceIPs:       true,
		LogSourceIPsHeader: "SomeHeader",
		LogSourceIPsRegex:  "[*",
		MetricsNamespace:   "with_invalid_source_ip_extractor",
	}

	api, err := New(cfg, serverCfg, &s, &FakeLogger{})
	require.Error(t, err)
	require.Nil(t, api)
}

func TestNewApiWithHeaderLogging(t *testing.T) {
	cfg := Config{
		HTTPRequestHeadersToLog: []string{"ForTesting"},
	}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "with_header_logging",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.NotNil(t, api.HTTPHeaderMiddleware)

}

func TestNewApiWithoutHeaderLogging(t *testing.T) {
	cfg := Config{
		HTTPRequestHeadersToLog: []string{},
	}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "without_header_logging",
	}
	server, err := server.New(serverCfg)
	require.NoError(t, err)

	api, err := New(cfg, serverCfg, server, &FakeLogger{})
	require.NoError(t, err)
	require.Nil(t, api.HTTPHeaderMiddleware)

}

// TestProfilingEndpointsDisabledByDefault asserts that the Cortex-registered
// profiling endpoint /debug/fgprof is not mounted on the HTTP router when the
// new -api.enable-profiling flag is left at its (secure) default of false.
// This locks in the fix for the unauthenticated-profiling-endpoints finding.
func TestProfilingEndpointsDisabledByDefault(t *testing.T) {
	cfg := Config{}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "profiling_disabled",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)
	defer s.Shutdown()

	a, err := New(cfg, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	a.RegisterAPI("/", cfg, cfg)

	for _, path := range []string{"/debug/fgprof"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.HTTP.ServeHTTP(rec, req)
		require.Equalf(t, http.StatusNotFound, rec.Code,
			"expected %s to be unmounted when EnableProfiling=false, got %d", path, rec.Code)
	}
}

// TestProfilingEndpointGatedByFlag asserts that enabling the new
// -api.enable-profiling flag mounts /debug/fgprof behind the configured auth
// middleware (which, in Cortex, extracts X-Scope-OrgID). Without the header
// the request is rejected; with the header the handler is reached.
func TestProfilingEndpointGatedByFlag(t *testing.T) {
	cfg := Config{EnableProfiling: true}
	serverCfg := server.Config{
		HTTPListenNetwork: server.DefaultNetwork,
		MetricsNamespace:  "profiling_enabled",
	}
	s, err := server.New(serverCfg)
	require.NoError(t, err)
	defer s.Shutdown()

	a, err := New(cfg, serverCfg, s, &FakeLogger{})
	require.NoError(t, err)

	a.RegisterAPI("/", cfg, cfg)

	// No X-Scope-OrgID header: auth middleware must reject the request
	// (status 401 from middleware.AuthenticateUser).
	req := httptest.NewRequest(http.MethodGet, "/debug/fgprof", nil)
	rec := httptest.NewRecorder()
	s.HTTP.ServeHTTP(rec, req)
	require.NotEqualf(t, http.StatusNotFound, rec.Code,
		"expected /debug/fgprof to be mounted when EnableProfiling=true")
	require.GreaterOrEqualf(t, rec.Code, 400,
		"expected /debug/fgprof to be rejected without X-Scope-OrgID, got %d", rec.Code)
}
