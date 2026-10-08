package querytee

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	errMinBackends = errors.New("at least 1 backend is required")
)

type ProxyConfig struct {
	ServerServiceAddress           string
	ServerServicePort              int
	BackendEndpoints               string
	PreferredBackend               string
	BackendReadTimeout             time.Duration
	CompareResponses               bool
	ValueComparisonTolerance       float64
	PassThroughNonRegisteredRoutes bool
	// PassThroughRoutesAllowlist is an optional comma-separated list of path
	// prefixes that may be reached through the catch-all pass-through handler.
	// If empty while PassThroughNonRegisteredRoutes is enabled, the entire
	// non-registered surface is forwarded (legacy behaviour).
	PassThroughRoutesAllowlist string

	// BackendTenantID, if set, pins the X-Scope-OrgID header forwarded to the
	// backend to this value regardless of what the client sent. It is mutually
	// exclusive with ProxyAllowedTenants.
	BackendTenantID string
	// ProxyAllowedTenants, if non-empty, restricts the set of X-Scope-OrgID
	// values that query-tee will forward to the backends. Comma-separated.
	ProxyAllowedTenants string

	// Client-side authentication for the query-tee listener itself. If
	// ClientBasicAuthUsername is set, every request to the listener (except
	// the health-check route) must present matching HTTP basic auth.
	ClientBasicAuthUsername string
	ClientBasicAuthPassword string
}

func (cfg *ProxyConfig) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&cfg.ServerServiceAddress, "server.service-address", "", "The network interface address where the query-tee service listens to. Defaults to all interfaces; set to 127.0.0.1 or an internal interface to avoid exposing the proxy to untrusted callers.")
	f.IntVar(&cfg.ServerServicePort, "server.service-port", 80, "The port where the query-tee service listens to.")
	f.StringVar(&cfg.BackendEndpoints, "backend.endpoints", "", "Comma separated list of backend endpoints to query.")
	f.StringVar(&cfg.PreferredBackend, "backend.preferred", "", "The hostname of the preferred backend when selecting the response to send back to the client. If no preferred backend is configured then the query-tee will send back to the client the first successful response received without waiting for other backends.")
	f.DurationVar(&cfg.BackendReadTimeout, "backend.read-timeout", 90*time.Second, "The timeout when reading the response from a backend.")
	f.BoolVar(&cfg.CompareResponses, "proxy.compare-responses", false, "Compare responses between preferred and secondary endpoints for supported routes.")
	f.Float64Var(&cfg.ValueComparisonTolerance, "proxy.value-comparison-tolerance", 0.000001, "The tolerance to apply when comparing floating point values in the responses. 0 to disable tolerance and require exact match (not recommended).")
	f.BoolVar(&cfg.PassThroughNonRegisteredRoutes, "proxy.passthrough-non-registered-routes", false, "Passthrough requests for non-registered routes to preferred backend. SECURITY: do not enable on a listener reachable by untrusted clients; combine with -proxy.passthrough-routes-allowlist and -proxy.client-basic-auth-username.")
	f.StringVar(&cfg.PassThroughRoutesAllowlist, "proxy.passthrough-routes-allowlist", "", "Comma-separated list of path prefixes that may be forwarded by the pass-through catch-all handler when -proxy.passthrough-non-registered-routes is enabled. If empty, every non-registered path is forwarded.")
	f.StringVar(&cfg.BackendTenantID, "backend.tenant-id", "", "If set, pins the X-Scope-OrgID header forwarded to every backend request to this value regardless of what the client sent. Mutually exclusive with -proxy.allowed-tenants. Strongly recommended whenever -backend.endpoints embeds credentials.")
	f.StringVar(&cfg.ProxyAllowedTenants, "proxy.allowed-tenants", "", "Comma-separated allowlist of X-Scope-OrgID values that query-tee will accept and forward to the backends. Requests whose header is not in the allowlist are rejected. Mutually exclusive with -backend.tenant-id.")
	f.StringVar(&cfg.ClientBasicAuthUsername, "proxy.client-basic-auth-username", "", "If set, every request to the query-tee listener (except the health-check at /) must present matching HTTP basic auth. Combine with -proxy.client-basic-auth-password.")
	f.StringVar(&cfg.ClientBasicAuthPassword, "proxy.client-basic-auth-password", "", "Password paired with -proxy.client-basic-auth-username.")
}

type Route struct {
	Path               string
	RouteName          string
	Methods            []string
	ResponseComparator ResponsesComparator
}

type Proxy struct {
	cfg      ProxyConfig
	backends []*ProxyBackend
	logger   log.Logger
	metrics  *ProxyMetrics
	routes   []Route

	// The HTTP server used to run the proxy service.
	srv         *http.Server
	srvListener net.Listener

	// Wait group used to wait until the server has done.
	done sync.WaitGroup
}

func NewProxy(cfg ProxyConfig, logger log.Logger, routes []Route, registerer prometheus.Registerer) (*Proxy, error) {
	if cfg.CompareResponses && cfg.PreferredBackend == "" {
		return nil, fmt.Errorf("when enabling comparison of results -backend.preferred flag must be set to hostname of preferred backend")
	}

	if cfg.PassThroughNonRegisteredRoutes && cfg.PreferredBackend == "" {
		return nil, fmt.Errorf("when enabling passthrough for non-registered routes -backend.preferred flag must be set to hostname of backend where those requests needs to be passed")
	}

	if cfg.BackendTenantID != "" && cfg.ProxyAllowedTenants != "" {
		return nil, fmt.Errorf("-backend.tenant-id and -proxy.allowed-tenants are mutually exclusive")
	}

	if (cfg.ClientBasicAuthUsername != "") != (cfg.ClientBasicAuthPassword != "") {
		return nil, fmt.Errorf("both -proxy.client-basic-auth-username and -proxy.client-basic-auth-password must be set together")
	}

	var allowedTenants []string
	if cfg.ProxyAllowedTenants != "" {
		for _, t := range strings.Split(cfg.ProxyAllowedTenants, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				allowedTenants = append(allowedTenants, t)
			}
		}
	}

	p := &Proxy{
		cfg:     cfg,
		logger:  logger,
		metrics: NewProxyMetrics(registerer),
		routes:  routes,
	}

	// Parse the backend endpoints (comma separated).
	parts := strings.Split(cfg.BackendEndpoints, ",")

	for idx, part := range parts {
		// Skip empty ones.
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		u, err := url.Parse(part)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid backend endpoint %s", part)
		}

		// The backend name is hardcoded as the backend hostname.
		name := u.Hostname()
		preferred := name == cfg.PreferredBackend

		// In tests we have the same hostname for all backends, so we also
		// support a numeric preferred backend which is the index in the list
		// of backends.
		if preferredIdx, err := strconv.Atoi(cfg.PreferredBackend); err == nil {
			preferred = preferredIdx == idx
		}

		p.backends = append(p.backends, NewProxyBackendWithTenants(name, u, cfg.BackendReadTimeout, preferred, cfg.BackendTenantID, allowedTenants))
	}

	// At least 1 backend is required
	if len(p.backends) < 1 {
		return nil, errMinBackends
	}

	// If the preferred backend is configured, then it must exists among the actual backends.
	if cfg.PreferredBackend != "" {
		exists := false
		for _, b := range p.backends {
			if b.preferred {
				exists = true
				break
			}
		}

		if !exists {
			return nil, fmt.Errorf("the preferred backend (hostname) has not been found among the list of configured backends")
		}
	}

	if cfg.CompareResponses && len(p.backends) != 2 {
		return nil, fmt.Errorf("when enabling comparison of results number of backends should be 2 exactly")
	}

	// At least 2 backends are suggested
	if len(p.backends) < 2 {
		level.Warn(p.logger).Log("msg", "The proxy is running with only 1 backend. At least 2 backends are required to fulfil the purpose of the proxy and compare results.")
	}

	// Loudly warn about insecure deployment configurations.
	if cfg.ClientBasicAuthUsername == "" {
		level.Warn(p.logger).Log(
			"msg", "query-tee listener has no client authentication configured; deploy only on a network unreachable by untrusted callers",
			"recommendation", "set -proxy.client-basic-auth-username/-password and/or -server.service-address to an internal interface",
		)
	}
	if cfg.BackendTenantID == "" && cfg.ProxyAllowedTenants == "" {
		for _, b := range p.backends {
			if b.endpoint.User.Username() != "" {
				level.Warn(p.logger).Log(
					"msg", "backend endpoint embeds credentials but neither -backend.tenant-id nor -proxy.allowed-tenants is set; any caller reaching the listener can read any tenant from the backend",
					"backend", b.name,
				)
				break
			}
		}
	}

	return p, nil
}

func (p *Proxy) Start() error {
	// Setup listener first, so we can fail early if the port is in use.
	// Default to all interfaces when no explicit address was configured
	// (preserves the historical behaviour).
	listener, err := net.Listen("tcp", net.JoinHostPort(p.cfg.ServerServiceAddress, strconv.Itoa(p.cfg.ServerServicePort)))
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	// Client-side authentication middleware (applied to every route except the
	// unauthenticated health-check so that liveness probes keep working).
	authMiddleware := p.authenticateClientMiddleware()

	// Health check endpoint — explicitly left unauthenticated.
	router.Path("/").Methods("GET").Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// register routes
	for _, route := range p.routes {
		var comparator ResponsesComparator
		if p.cfg.CompareResponses {
			comparator = route.ResponseComparator
		}
		router.Path(route.Path).Methods(route.Methods...).Handler(authMiddleware(NewProxyEndpoint(p.backends, route.RouteName, p.metrics, p.logger, comparator)))
	}

	if p.cfg.PassThroughNonRegisteredRoutes {
		allowedPrefixes := parseCSV(p.cfg.PassThroughRoutesAllowlist)
		for _, backend := range p.backends {
			if backend.preferred {
				rp := httputil.NewSingleHostReverseProxy(backend.endpoint)
				var handler http.Handler = rp
				if len(allowedPrefixes) > 0 {
					handler = restrictPassthroughRoutes(allowedPrefixes, rp)
				}
				router.PathPrefix("/").Handler(authMiddleware(handler))
				break
			}
		}
	}

	p.srvListener = listener
	p.srv = &http.Server{
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 2 * time.Minute,
		Handler:      router,
	}

	// Run in a dedicated goroutine.
	p.done.Add(1)
	go func() {
		defer p.done.Done()

		if err := p.srv.Serve(p.srvListener); err != nil {
			level.Error(p.logger).Log("msg", "Proxy server failed", "err", err)
		}
	}()

	level.Info(p.logger).Log("msg", "The proxy is up and running.")
	return nil
}

func (p *Proxy) Stop() error {
	if p.srv == nil {
		return nil
	}

	return p.srv.Shutdown(context.Background())
}

func (p *Proxy) Await() {
	// Wait until terminated.
	p.done.Wait()
}

func (p *Proxy) Endpoint() string {
	if p.srvListener == nil {
		return ""
	}

	return p.srvListener.Addr().String()
}

// authenticateClientMiddleware returns a middleware that enforces client-side
// basic-auth on the listener. If no credentials are configured on the proxy,
// the returned middleware is a pass-through (preserves historical behaviour).
func (p *Proxy) authenticateClientMiddleware() func(http.Handler) http.Handler {
	wantUser := p.cfg.ClientBasicAuthUsername
	wantPass := p.cfg.ClientBasicAuthPassword
	if wantUser == "" && wantPass == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, ok := r.BasicAuth()
			if !ok ||
				subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) != 1 ||
				subtle.ConstantTimeCompare([]byte(gotPass), []byte(wantPass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="query-tee"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// restrictPassthroughRoutes wraps the pass-through reverse proxy and returns
// 404 for any request whose path does not match one of the allowlisted
// prefixes.
func restrictPassthroughRoutes(allowedPrefixes []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, pfx := range allowedPrefixes {
			if strings.HasPrefix(r.URL.Path, pfx) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
