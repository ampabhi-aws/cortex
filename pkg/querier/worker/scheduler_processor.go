package worker

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/backoff"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	cortexmiddleware "github.com/cortexproject/cortex/pkg/util/middleware"
	"github.com/cortexproject/cortex/pkg/util/services"
)

func newSchedulerProcessor(cfg Config, handler RequestHandler, log log.Logger, reg prometheus.Registerer) (*schedulerProcessor, []services.Service) {
	p := &schedulerProcessor{
		log:            log,
		handler:        handler,
		maxMessageSize: cfg.GRPCClientConfig.MaxSendMsgSize,
		querierID:      cfg.QuerierID,
		grpcConfig:     cfg.GRPCClientConfig,

		frontendClientRequestDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cortex_querier_query_frontend_request_duration_seconds",
			Help:    "Time spend doing requests to frontend.",
			Buckets: prometheus.ExponentialBuckets(0.001, 4, 6),
		}, []string{"operation", "status_code"}),
	}

	frontendClientsGauge := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Name: "cortex_querier_query_frontend_clients",
		Help: "The current number of clients connected to query-frontend.",
	})

	poolConfig := client.PoolConfig{
		CheckInterval:      5 * time.Second,
		HealthCheckEnabled: true,
		HealthCheckTimeout: 1 * time.Second,
	}

	p.frontendPool = client.NewPool("frontend", poolConfig, nil, p.createFrontendClient, frontendClientsGauge, log)
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
			// The scheduler's gRPC server is unauthenticated in the default
			// Cortex deployment, so request.UserID and request.FrontendAddress
			// are attacker-controlled on paths that reach the scheduler without
			// a trusted reverse proxy. Validate / sanitize them before using
			// them to execute a query or to dial a result-callback connection.
			if err := validateSchedulerRequest(request); err != nil {
				level.Warn(sp.log).Log("msg", "rejecting malformed scheduler request", "err", err, "addr", address)
				if sendErr := c.Send(&schedulerpb.QuerierToScheduler{}); sendErr != nil {
					level.Error(sp.log).Log("msg", "error notifying scheduler about rejected query", "err", sendErr, "addr", address)
				}
				return
			}

			// Overwrite any X-Scope-OrgID header in the inner HTTPRequest so the
			// authoritative tenant used by the querier's internal AuthMiddleware
			// always matches request.UserID. Without this a caller could set a
			// different inner header to reach another tenant's data (the
			// httpgrpc server rebuilds a real http.Request from these headers).
			sanitizeOrgIDHeader(request.HttpRequest, request.UserID)

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
	if err := validateFrontendCallbackAddress(addr); err != nil {
		return nil, err
	}
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

// validateSchedulerRequest applies the documented tenant-ID charset / length
// limit to the externally-supplied UserID and rejects FrontendAddress values
// that could be used to coerce an outbound dial to an attacker-selected gRPC
// resolver target (unix sockets, dns:// targets, etc.).
func validateSchedulerRequest(req *schedulerpb.SchedulerToQuerier) error {
	if req == nil {
		return fmt.Errorf("nil scheduler request")
	}
	for _, part := range strings.Split(req.UserID, "|") {
		if err := tenant.ValidTenantID(part); err != nil {
			return err
		}
	}
	return validateFrontendCallbackAddress(req.FrontendAddress)
}

// validateFrontendCallbackAddress rejects gRPC target strings that would make
// the querier dial an attacker-chosen scheme (unix:/path, dns:///..., etc.)
// or an absolute filesystem path.
func validateFrontendCallbackAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty frontend callback address")
	}
	if len(addr) > 253 {
		return fmt.Errorf("frontend callback address too long")
	}
	if strings.ContainsAny(addr, "\x00\n\r\t ") {
		return fmt.Errorf("frontend callback address contains invalid characters")
	}
	if strings.HasPrefix(addr, "/") {
		return fmt.Errorf("frontend callback address must not be an absolute path")
	}
	if i := strings.Index(addr, ":"); i > 0 {
		head := addr[:i]
		rest := addr[i+1:]
		if strings.HasPrefix(rest, "//") {
			return fmt.Errorf("frontend callback address must not include a URI scheme")
		}
		if head != "" && isAlphaOnly(head) && !isDigitsOnly(rest) && strings.ContainsAny(rest, "/\\") {
			return fmt.Errorf("frontend callback address must not be a gRPC resolver target")
		}
	}
	return nil
}

func isAlphaOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func isDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sanitizeOrgIDHeader replaces (or inserts) the X-Scope-OrgID header on an
// httpgrpc.HTTPRequest so that it unambiguously matches the authoritative
// tenant the querier will execute the request under. This prevents a caller
// that reaches the unauthenticated scheduler port from using a conflicting
// inner header to pivot into another tenant's data via the querier's
// internal AuthMiddleware.
func sanitizeOrgIDHeader(req *httpgrpc.HTTPRequest, userID string) {
	if req == nil {
		return
	}
	filtered := make([]*httpgrpc.Header, 0, len(req.Headers)+1)
	for _, h := range req.Headers {
		if h == nil {
			continue
		}
		if strings.EqualFold(h.Key, user.OrgIDHeaderName) {
			continue
		}
		filtered = append(filtered, h)
	}
	filtered = append(filtered, &httpgrpc.Header{
		Key:    user.OrgIDHeaderName,
		Values: []string{userID},
	})
	req.Headers = filtered
}
