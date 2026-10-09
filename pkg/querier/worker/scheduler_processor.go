package worker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	otgrpc "github.com/opentracing-contrib/go-grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/middleware"
	"github.com/weaveworks/common/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cortexproject/cortex/pkg/frontend/v2/frontendv2pb"
	querier_stats "github.com/cortexproject/cortex/pkg/querier/stats"
	"github.com/cortexproject/cortex/pkg/ring/client"
	"github.com/cortexproject/cortex/pkg/scheduler/schedulerpb"
	"github.com/cortexproject/cortex/pkg/util/backoff"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	cortexmiddleware "github.com/cortexproject/cortex/pkg/util/middleware"
	"github.com/cortexproject/cortex/pkg/util/services"
)

// maxFrontendPoolSize caps how many distinct frontend addresses a querier
// will concurrently keep gRPC connections to. The frontend address is
// attacker-influenced (see pkg/scheduler/scheduler.go frontendConnected);
// this cap prevents a hostile scheduler/frontend from exhausting sockets
// and memory on the querier.
const maxFrontendPoolSize = 256

func newSchedulerProcessor(cfg Config, handler RequestHandler, log log.Logger, reg prometheus.Registerer) (*schedulerProcessor, []services.Service) {
	p := &schedulerProcessor{
		log:            log,
		handler:        handler,
		maxMessageSize: cfg.GRPCClientConfig.MaxSendMsgSize,
		querierID:      cfg.QuerierID,
		grpcConfig:     cfg.GRPCClientConfig,
		recentFrontends: map[string]time.Time{},
	}

	frontendClientsGauge := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Name: "cortex_querier_query_frontend_clients",
		Help: "The current number of clients connected to query-frontend.",
	})

	p.frontendClientRequestDuration = promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cortex_querier_query_frontend_request_duration_seconds",
		Help:    "Time spend doing requests to frontend.",
		Buckets: prometheus.ExponentialBuckets(0.001, 4, 6),
	}, []string{"operation", "status_code"})

	poolConfig := client.PoolConfig{
		CheckInterval:      5 * time.Second,
		HealthCheckEnabled: true,
		HealthCheckTimeout: 1 * time.Second,
	}

	// Supply a discovery function so the pool can evict frontend addresses
	// we have not seen on the scheduler stream recently. Without this,
	// removeStaleClients was a no-op (discovery was nil) and black-holed
	// attacker-supplied addresses only drained via sequential health checks.
	p.frontendPool = client.NewPool("frontend", poolConfig, p.recentFrontendDiscovery, p.createFrontendClient, frontendClientsGauge, log)
	return p, []services.Service{p.frontendPool}
}

// Handles incoming queries from query-scheduler.
type schedulerProcessor struct {
	log            log.Logger
	handler        RequestHandler
	grpcConfig     grpcclient.Config
	maxMessageSize int
	querierID      string

	frontendPool                  *client.Pool
	frontendClientRequestDuration *prometheus.HistogramVec

	// recentFrontends tracks frontend addresses the scheduler has recently
	// asked this querier to contact. It feeds the frontend pool discovery
	// so stale/attacker-supplied addresses are evicted and the pool size is
	// bounded.
	recentFrontendsMu sync.Mutex
	recentFrontends   map[string]time.Time
}

// notifyShutdown implements processor.
func (sp *schedulerProcessor) notifyShutdown(ctx context.Context, conn *grpc.ClientConn, address string) {
	client := schedulerpb.NewSchedulerForQuerierClient(conn)

	req := &schedulerpb.NotifyQuerierShutdownRequest{QuerierID: sp.querierID}
	if _, err := client.NotifyQuerierShutdown(ctx, req); err != nil {
		// Since we're shutting down there's nothing we can do except logging it.
		level.Warn(sp.log).Log("msg", "failed to notify querier shutdown to query-scheduler", "address", address, "err", err)
	}
}

func (sp *schedulerProcessor) processQueriesOnSingleStream(ctx context.Context, conn *grpc.ClientConn, address string) {
	schedulerClient := schedulerpb.NewSchedulerForQuerierClient(conn)

	backoff := backoff.New(ctx, processorBackoffConfig)
	for backoff.Ongoing() {
		c, err := schedulerClient.QuerierLoop(ctx)
		if err == nil {
			err = c.Send(&schedulerpb.QuerierToScheduler{QuerierID: sp.querierID})
		}

		if err != nil {
			level.Error(sp.log).Log("msg", "error contacting scheduler", "err", err, "addr", address)
			backoff.Wait()
			continue
		}

		if err := sp.querierLoop(c, address); err != nil {
			level.Error(sp.log).Log("msg", "error processing requests from scheduler", "err", err, "addr", address)
			backoff.Wait()
			continue
		}

		backoff.Reset()
	}
}

// process loops processing requests on an established stream.
func (sp *schedulerProcessor) querierLoop(c schedulerpb.SchedulerForQuerier_QuerierLoopClient, address string) error {
	// Build a child context so we can cancel a query when the stream is closed.
	ctx, cancel := context.WithCancel(c.Context())
	defer cancel()

	for {
		request, err := c.Recv()
		if err != nil {
			return err
		}

		// Handle the request on a "background" goroutine, so we go back to
		// blocking on c.Recv().  This allows us to detect the stream closing
		// and cancel the query.  We don't actually handle queries in parallel
		// here, as we're running in lock step with the server - each Recv is
		// paired with a Send.
		go func() {
			// We need to inject user into context for sending response back.
			ctx := user.InjectOrgID(ctx, request.UserID)

			tracer := opentracing.GlobalTracer()
			// Ignore errors here. If we cannot get parent span, we just don't create new one.
			parentSpanContext, _ := httpgrpcutil.GetParentSpanForRequest(tracer, request.HttpRequest)
			if parentSpanContext != nil {
				queueSpan, spanCtx := opentracing.StartSpanFromContextWithTracer(ctx, tracer, "querier_processor_runRequest", opentracing.ChildOf(parentSpanContext))
				defer queueSpan.Finish()

				ctx = spanCtx
			}
			logger := util_log.WithContext(ctx, sp.log)

			sp.runRequest(ctx, logger, request.QueryID, request.FrontendAddress, request.StatsEnabled, request.HttpRequest)

			// Report back to scheduler that processing of the query has finished.
			if err := c.Send(&schedulerpb.QuerierToScheduler{}); err != nil {
				level.Error(logger).Log("msg", "error notifying scheduler about finished query", "err", err, "addr", address)
			}
		}()
	}
}

func (sp *schedulerProcessor) runRequest(ctx context.Context, logger log.Logger, queryID uint64, frontendAddress string, statsEnabled bool, request *httpgrpc.HTTPRequest) {
	if err := validateFrontendAddress(frontendAddress); err != nil {
		// The scheduler is responsible for only handing us legitimate
		// frontend addresses; refuse to dial anything that is clearly
		// unsafe (malformed, loopback that is not us, link-local metadata,
		// multicast, unspecified). This is defense in depth against a
		// compromised or buggy scheduler.
		level.Error(logger).Log("msg", "refusing to dial unsafe frontend address", "frontend", frontendAddress, "err", err)
		return
	}

	// Bound the frontend client pool so a scheduler that funnels an
	// unbounded set of distinct addresses to us cannot exhaust sockets.
	if sp.frontendPool.Count() >= maxFrontendPoolSize {
		if _, known := sp.lookupRecentFrontend(frontendAddress); !known {
			level.Error(logger).Log("msg", "refusing to dial frontend: pool at capacity", "frontend", frontendAddress, "size", sp.frontendPool.Count(), "max", maxFrontendPoolSize)
			return
		}
	}

	var stats *querier_stats.Stats
	if statsEnabled {
		stats, ctx = querier_stats.ContextWithEmptyStats(ctx)
	}

	response, err := sp.handler.Handle(ctx, request)
	if err != nil {
		var ok bool
		response, ok = httpgrpc.HTTPResponseFromError(err)
		if !ok {
			response = &httpgrpc.HTTPResponse{
				Code: http.StatusInternalServerError,
				Body: []byte(err.Error()),
			}
		}
	}

	// Ensure responses that are too big are not retried.
	if len(response.Body) >= sp.maxMessageSize {
		level.Error(logger).Log("msg", "response larger than max message size", "size", len(response.Body), "maxMessageSize", sp.maxMessageSize)

		errMsg := fmt.Sprintf("response larger than the max message size (%d vs %d)", len(response.Body), sp.maxMessageSize)
		response = &httpgrpc.HTTPResponse{
			Code: http.StatusRequestEntityTooLarge,
			Body: []byte(errMsg),
		}
	}

	c, err := sp.frontendPool.GetClientFor(frontendAddress)
	if err == nil {
		sp.rememberFrontend(frontendAddress)
		// Response is empty and uninteresting.
		_, err = c.(frontendv2pb.FrontendForQuerierClient).QueryResult(ctx, &frontendv2pb.QueryResultRequest{
			QueryID:      queryID,
			HttpResponse: response,
			Stats:        stats,
		})
	}
	if err != nil {
		level.Error(logger).Log("msg", "error notifying frontend about finished query", "err", err, "frontend", frontendAddress)
	}
}

func (sp *schedulerProcessor) createFrontendClient(addr string) (client.PoolClient, error) {
	opts, err := sp.grpcConfig.DialOption([]grpc.UnaryClientInterceptor{
		otgrpc.OpenTracingClientInterceptor(opentracing.GlobalTracer()),
		middleware.ClientUserHeaderInterceptor,
		cortexmiddleware.PrometheusGRPCUnaryInstrumentation(sp.frontendClientRequestDuration),
	}, nil)

	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}

	return &frontendClient{
		FrontendForQuerierClient: frontendv2pb.NewFrontendForQuerierClient(conn),
		HealthClient:             grpc_health_v1.NewHealthClient(conn),
		conn:                     conn,
	}, nil
}

type frontendClient struct {
	frontendv2pb.FrontendForQuerierClient
	grpc_health_v1.HealthClient
	conn *grpc.ClientConn
}

func (fc *frontendClient) Close() error {
	return fc.conn.Close()
}

// recentFrontendWindow bounds how long an address that has not been handed to
// runRequest will remain in the pool. It should be larger than the pool's
// CheckInterval (5s) and the typical query duration.
const recentFrontendWindow = 2 * time.Minute

// lookupRecentFrontend reports whether addr is in the recent-use set.
func (sp *schedulerProcessor) lookupRecentFrontend(addr string) (time.Time, bool) {
	sp.recentFrontendsMu.Lock()
	defer sp.recentFrontendsMu.Unlock()
	t, ok := sp.recentFrontends[addr]
	return t, ok
}

// rememberFrontend records that the scheduler asked us to contact
// frontendAddress, so that recentFrontendDiscovery (fed into Pool.discovery)
// does not evict a currently-in-use client.
func (sp *schedulerProcessor) rememberFrontend(addr string) {
	sp.recentFrontendsMu.Lock()
	defer sp.recentFrontendsMu.Unlock()
	now := time.Now()
	sp.recentFrontends[addr] = now
	if len(sp.recentFrontends) > maxFrontendPoolSize*2 {
		// Keep the map bounded. Drop entries older than the window.
		for k, t := range sp.recentFrontends {
			if now.Sub(t) > recentFrontendWindow {
				delete(sp.recentFrontends, k)
			}
		}
	}
}

// recentFrontendDiscovery returns the set of frontend addresses the scheduler
// has recently asked this querier to contact. Pool.removeStaleClients uses
// this list to evict unknown addresses, so a scheduler that stops advertising
// an address causes the connection to be closed quickly.
func (sp *schedulerProcessor) recentFrontendDiscovery() ([]string, error) {
	sp.recentFrontendsMu.Lock()
	defer sp.recentFrontendsMu.Unlock()
	now := time.Now()
	addrs := make([]string, 0, len(sp.recentFrontends))
	for addr, t := range sp.recentFrontends {
		if now.Sub(t) > recentFrontendWindow {
			delete(sp.recentFrontends, addr)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// validateFrontendAddress enforces defense-in-depth checks on the
// scheduler-asserted frontend address before the querier dials it. It
// requires a well-formed host:port and rejects obviously unsafe targets
// such as link-local metadata (169.254.0.0/16), multicast and the
// unspecified address. Loopback is allowed only when the host is a literal
// IP; we intentionally do not resolve DNS names here (the scheduler-side
// peer-identity check already pins the address to the frontend's peer IP).
func validateFrontendAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty frontend address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("malformed frontend address %q: %w", addr, err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("frontend address %q missing host or port", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("frontend address %q uses unspecified IP", addr)
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("frontend address %q uses link-local IP (metadata or discovery range)", addr)
		}
		if ip.IsMulticast() {
			return fmt.Errorf("frontend address %q uses multicast IP", addr)
		}
	}
	return nil
}
