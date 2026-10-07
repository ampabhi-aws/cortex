package scheduler

import (
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	otgrpc "github.com/opentracing-contrib/go-grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/middleware"
	"github.com/weaveworks/common/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/cortexproject/cortex/pkg/frontend/v2/frontendv2pb"
	"github.com/cortexproject/cortex/pkg/scheduler/queue"
	"github.com/cortexproject/cortex/pkg/scheduler/schedulerpb"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	"github.com/cortexproject/cortex/pkg/util/services"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

var (
	errSchedulerIsNotRunning = errors.New("scheduler is not running")
)

// Scheduler is responsible for queueing and dispatching queries to Queriers.
type Scheduler struct {
	services.Service

	cfg Config
	log log.Logger

	limits Limits

	connectedFrontendsMu sync.Mutex
	connectedFrontends   map[string]*connectedFrontend

	requestQueue *queue.RequestQueue
	activeUsers  *util.ActiveUsersCleanupService

	pendingRequestsMu sync.Mutex
	pendingRequests   map[requestKey]*schedulerRequest // Request is kept in this map even after being dispatched to querier. It can still be canceled at that time.

	// Subservices manager.
	subservices        *services.Manager
	subservicesWatcher *services.FailureWatcher

	// Metrics.
	queueLength              *prometheus.GaugeVec
	discardedRequests        *prometheus.CounterVec
	connectedQuerierClients  prometheus.GaugeFunc
	connectedFrontendClients prometheus.GaugeFunc
	queueDuration            prometheus.Histogram
}

type requestKey struct {
	frontendAddr string
	queryID      uint64
}

type connectedFrontend struct {
	connections int

	// This context is used for running all queries from the same frontend.
	// When last frontend connection is closed, context is canceled.
	ctx    context.Context
	cancel context.CancelFunc
}

type Config struct {
	MaxOutstandingPerTenant int               `yaml:"max_outstanding_requests_per_tenant"`
	QuerierForgetDelay      time.Duration     `yaml:"querier_forget_delay"`
	GRPCClientConfig        grpcclient.Config `yaml:"grpc_client_config" doc:"description=This configures the gRPC client used to report errors back to the query-frontend."`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.IntVar(&cfg.MaxOutstandingPerTenant, "query-scheduler.max-outstanding-requests-per-tenant", 100, "Maximum number of outstanding requests per tenant per query-scheduler. In-flight requests above this limit will fail with HTTP response status code 429.")
	f.DurationVar(&cfg.QuerierForgetDelay, "query-scheduler.querier-forget-delay", 0, "If a querier disconnects without sending notification about graceful shutdown, the query-scheduler will keep the querier in the tenant's shard until the forget delay has passed. This feature is useful to reduce the blast radius when shuffle-sharding is enabled.")
	cfg.GRPCClientConfig.RegisterFlagsWithPrefix("query-scheduler.grpc-client-config", f)
}

// NewScheduler creates a new Scheduler.
func NewScheduler(cfg Config, limits Limits, log log.Logger, registerer prometheus.Registerer) (*Scheduler, error) {
	s := &Scheduler{
		cfg:    cfg,
		log:    log,
		limits: limits,

		pendingRequests:    map[requestKey]*schedulerRequest{},
		connectedFrontends: map[string]*connectedFrontend{},
	}

	s.queueLength = promauto.With(registerer).NewGaugeVec(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_queue_length",
		Help: "Number of queries in the queue.",
	}, []string{"user"})

	s.discardedRequests = promauto.With(registerer).NewCounterVec(prometheus.CounterOpts{
		Name: "cortex_query_scheduler_discarded_requests_total",
		Help: "Total number of query requests discarded.",
	}, []string{"user"})
	s.requestQueue = queue.NewRequestQueue(cfg.MaxOutstandingPerTenant, cfg.QuerierForgetDelay, s.queueLength, s.discardedRequests)

	s.queueDuration = promauto.With(registerer).NewHistogram(prometheus.HistogramOpts{
		Name:    "cortex_query_scheduler_queue_duration_seconds",
		Help:    "Time spend by requests in queue before getting picked up by a querier.",
		Buckets: prometheus.DefBuckets,
	})
	s.connectedQuerierClients = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_connected_querier_clients",
		Help: "Number of querier worker clients currently connected to the query-scheduler.",
	}, s.requestQueue.GetConnectedQuerierWorkersMetric)
	s.connectedFrontendClients = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_connected_frontend_clients",
		Help: "Number of query-frontend worker clients currently connected to the query-scheduler.",
	}, s.getConnectedFrontendClientsMetric)

	s.activeUsers = util.NewActiveUsersCleanupWithDefaultValues(s.cleanupMetricsForInactiveUser)

	var err error
	s.subservices, err = services.NewManager(s.requestQueue, s.activeUsers)
	if err != nil {
		return nil, err
	}

	s.Service = services.NewBasicService(s.starting, s.running, s.stopping)
	return s, nil
}

// Limits needed for the Query Scheduler - interface used for decoupling.
type Limits interface {
	// MaxQueriersPerUser returns max queriers to use per tenant, or 0 if shuffle sharding is disabled.
	MaxQueriersPerUser(user string) int
}

type schedulerRequest struct {
	frontendAddress string
	userID          string
	queryID         uint64
	request         *httpgrpc.HTTPRequest
	statsEnabled    bool

	enqueueTime time.Time

	ctx       context.Context
	ctxCancel context.CancelFunc
	queueSpan opentracing.Span

	// This is only used for testing.
	parentSpanContext opentracing.SpanContext
}

// FrontendLoop handles connection from frontend.
func (s *Scheduler) FrontendLoop(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) error {
	frontendAddress, frontendCtx, err := s.frontendConnected(frontend)
	if err != nil {
		return err
	}
	defer s.frontendDisconnected(frontendAddress)

	// Response to INIT. If scheduler is not running, we skip for-loop, send SHUTTING_DOWN and exit this method.
	if s.State() == services.Running {
		if err := frontend.Send(&schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}); err != nil {
			return err
		}
	}

	// We stop accepting new queries in Stopping state. By returning quickly, we disconnect frontends, which in turns
	// cancels all their queries.
	for s.State() == services.Running {
		msg, err := frontend.Recv()
		if err != nil {
			// No need to report this as error, it is expected when query-frontend performs SendClose() (as frontendSchedulerWorker does).
			if err == io.EOF {
				return nil
			}
			return err
		}

		if s.State() != services.Running {
			break // break out of the loop, and send SHUTTING_DOWN message.
		}

		var resp *schedulerpb.SchedulerToFrontend

		switch msg.GetType() {
		case schedulerpb.ENQUEUE:
			err = s.enqueueRequest(frontendCtx, frontendAddress, msg)
			switch {
			case err == nil:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}
			case err == queue.ErrTooManyRequests:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.TOO_MANY_REQUESTS_PER_TENANT}
			default:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
			}

		case schedulerpb.CANCEL:
			s.cancelRequestAndRemoveFromPending(frontendAddress, msg.QueryID)
			resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}

		default:
			level.Error(s.log).Log("msg", "unknown request type from frontend", "addr", frontendAddress, "type", msg.GetType())
			return errors.New("unknown request type")
		}

		err = frontend.Send(resp)
		// Failure to send response results in ending this connection.
		if err != nil {
			return err
		}
	}

	// Report shutdown back to frontend, so that it can retry with different scheduler. Also stop the frontend loop.
	return frontend.Send(&schedulerpb.SchedulerToFrontend{Status: schedulerpb.SHUTTING_DOWN})
}

func (s *Scheduler) frontendConnected(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) (string, context.Context, error) {
	msg, err := frontend.Recv()
	if err != nil {
		return "", nil, err
	}
	if msg.Type != schedulerpb.INIT || msg.FrontendAddress == "" {
		return "", nil, errors.New("no frontend address")
	}
	if err := validateFrontendAddress(msg.FrontendAddress); err != nil {
		level.Warn(s.log).Log("msg", "rejecting frontend INIT with invalid address", "addr", msg.FrontendAddress, "err", err)
		return "", nil, err
	}
	// Defence in depth: ensure the advertised FrontendAddress is at least
	// plausibly reachable to the stream peer. We do not require an exact
	// match (NAT / service discovery can legitimately rewrite host:port) but
	// we reject obvious host-spoofing where the advertised host is a
	// different concrete IP than the peer's connecting address. Unresolved
	// hostnames and loopback/unknown peers are allowed through.
	if p, ok := peer.FromContext(frontend.Context()); ok && p != nil && p.Addr != nil {
		if err := checkFrontendAddressMatchesPeer(msg.FrontendAddress, p.Addr.String()); err != nil {
			level.Warn(s.log).Log("msg", "rejecting frontend INIT with address not matching peer", "addr", msg.FrontendAddress, "peer", p.Addr.String(), "err", err)
			return "", nil, err
		}
	}

	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	cf := s.connectedFrontends[msg.FrontendAddress]
	if cf == nil {
		cf = &connectedFrontend{
			connections: 0,
		}
		cf.ctx, cf.cancel = context.WithCancel(context.Background())
		s.connectedFrontends[msg.FrontendAddress] = cf
	}

	cf.connections++
	return msg.FrontendAddress, cf.ctx, nil
}

// validateFrontendAddress rejects FrontendAddress strings that could be used
// to coerce the scheduler or querier into dialing an arbitrary gRPC target
// scheme (e.g. "unix:/path", "dns:///...", "passthrough:///...") or that
// contain obviously malformed characters. Legitimate frontend addresses are
// bare host:port strings; opaque labels used in unit tests ("frontend-12345")
// are also permitted.
func validateFrontendAddress(addr string) error {
	if addr == "" {
		return errors.New("empty frontend address")
	}
	if len(addr) > 253 { // generous upper bound; longest DNS name is 253
		return errors.New("frontend address too long")
	}
	if strings.ContainsAny(addr, "\x00\n\r\t ") {
		return errors.New("frontend address contains invalid characters")
	}
	// Reject gRPC name-resolver schemes and absolute paths which could
	// otherwise be used to coerce an outbound dial to a unix socket or an
	// attacker-controlled resolver target.
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "//") {
		return errors.New("frontend address must not be an absolute path")
	}
	if i := strings.Index(addr, ":"); i > 0 {
		head := addr[:i]
		rest := addr[i+1:]
		// Any gRPC resolver scheme is of the form "<scheme>://..." (two
		// slashes), while a legitimate host:port after the first colon is
		// a plain port number (digits only).
		if strings.HasPrefix(rest, "//") {
			return errors.New("frontend address must not include a URI scheme")
		}
		// If head looks like a scheme (letters only, non-numeric) and rest
		// is not a numeric port, it may be a resolver target such as
		// "unix:/var/run/x" or "dns:example". Reject those.
		if head != "" && isAlpha(head) && !isNumericPort(rest) && strings.ContainsAny(rest, "/\\") {
			return errors.New("frontend address must not be a gRPC resolver target")
		}
	}
	return nil
}

func isAlpha(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return len(s) > 0
}

func isNumericPort(s string) bool {
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

// checkFrontendAddressMatchesPeer returns nil when the advertised address
// cannot be shown to disagree with the peer's connecting address. It only
// errors when both resolve to concrete, incompatible IP literals.
func checkFrontendAddressMatchesPeer(advertised, peerAddr string) error {
	advHost, _, err := net.SplitHostPort(advertised)
	if err != nil {
		// Not host:port (could be an opaque label or hostname-only). Nothing
		// to compare; allow it through.
		return nil
	}
	peerHost, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return nil
	}
	advIP := net.ParseIP(advHost)
	peerIP := net.ParseIP(peerHost)
	if advIP == nil || peerIP == nil {
		return nil
	}
	if peerIP.IsLoopback() || peerIP.IsUnspecified() {
		return nil
	}
	if !advIP.Equal(peerIP) {
		return errors.New("advertised frontend address does not match stream peer")
	}
	return nil
}

func (s *Scheduler) frontendDisconnected(frontendAddress string) {
	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	cf := s.connectedFrontends[frontendAddress]
	cf.connections--
	if cf.connections == 0 {
		delete(s.connectedFrontends, frontendAddress)
		cf.cancel()
	}
}

func (s *Scheduler) enqueueRequest(frontendContext context.Context, frontendAddr string, msg *schedulerpb.FrontendToScheduler) error {
	// Create new context for this request, to support cancellation.
	ctx, cancel := context.WithCancel(frontendContext)
	shouldCancel := true
	defer func() {
		if shouldCancel {
			cancel()
		}
	}()

	// Extract tracing information from headers in HTTP request. FrontendContext doesn't have the correct tracing
	// information, since that is a long-running request.
	tracer := opentracing.GlobalTracer()
	parentSpanContext, err := httpgrpcutil.GetParentSpanForRequest(tracer, msg.HttpRequest)
	if err != nil {
		return err
	}

	userID := msg.GetUserID()

	// Validate the tenant ID carried in the message body. The scheduler's
	// gRPC interface is reachable without authentication in the default
	// Cortex deployment and the UserID is attacker-controlled, so we apply
	// the documented tenant-ID charset and length limits before it is used
	// as a queue key or metric label. For multi-tenant requests, each
	// component is validated independently.
	for _, part := range strings.Split(userID, "|") {
		if err := tenant.ValidTenantID(part); err != nil {
			return err
		}
	}

	// Defence in depth: refuse to enqueue a request whose inner
	// X-Scope-OrgID header disagrees with the UserID field. A legitimate
	// query-frontend derives both from the same authenticated tenant;
	// a mismatch is a strong signal of a forged ENQUEUE attempting
	// cross-tenant access against the querier's internal API.
	if hdr := orgIDHeader(msg.HttpRequest); hdr != "" && hdr != userID {
		return errors.New("tenant mismatch between HTTP X-Scope-OrgID header and UserID")
	}

	req := &schedulerRequest{
		frontendAddress: frontendAddr,
		userID:          msg.UserID,
		queryID:         msg.QueryID,
		request:         msg.HttpRequest,
		statsEnabled:    msg.StatsEnabled,
	}

	now := time.Now()

	req.parentSpanContext = parentSpanContext
	req.queueSpan, req.ctx = opentracing.StartSpanFromContextWithTracer(ctx, tracer, "queued", opentracing.ChildOf(parentSpanContext))
	req.enqueueTime = now
	req.ctxCancel = cancel

	// aggregate the max queriers limit in the case of a multi tenant query
	tenantIDs, err := tenant.TenantIDsFromOrgID(userID)
	if err != nil {
		return err
	}
	maxQueriers := validation.SmallestPositiveNonZeroIntPerTenant(tenantIDs, s.limits.MaxQueriersPerUser)

	s.activeUsers.UpdateUserTimestamp(userID, now)
	return s.requestQueue.EnqueueRequest(userID, req, maxQueriers, func() {
		shouldCancel = false

		s.pendingRequestsMu.Lock()
		defer s.pendingRequestsMu.Unlock()
		s.pendingRequests[requestKey{frontendAddr: frontendAddr, queryID: msg.QueryID}] = req
	})
}

// This method doesn't do removal from the queue.
func (s *Scheduler) cancelRequestAndRemoveFromPending(frontendAddr string, queryID uint64) {
	s.pendingRequestsMu.Lock()
	defer s.pendingRequestsMu.Unlock()

	key := requestKey{frontendAddr: frontendAddr, queryID: queryID}
	req := s.pendingRequests[key]
	if req != nil {
		req.ctxCancel()
	}
	delete(s.pendingRequests, key)
}

// QuerierLoop is started by querier to receive queries from scheduler.
func (s *Scheduler) QuerierLoop(querier schedulerpb.SchedulerForQuerier_QuerierLoopServer) error {
	resp, err := querier.Recv()
	if err != nil {
		return err
	}

	querierID := resp.GetQuerierID()

	s.requestQueue.RegisterQuerierConnection(querierID)
	defer s.requestQueue.UnregisterQuerierConnection(querierID)

	// If the downstream connection to querier is cancelled,
	// we need to ping the condition variable to unblock getNextRequestForQuerier.
	// Ideally we'd have ctx aware condition variables...
	go func() {
		<-querier.Context().Done()
		s.requestQueue.QuerierDisconnecting()
	}()

	lastUserIndex := queue.FirstUser()

	// In stopping state scheduler is not accepting new queries, but still dispatching queries in the queues.
	for s.isRunningOrStopping() {
		req, idx, err := s.requestQueue.GetNextRequestForQuerier(querier.Context(), lastUserIndex, querierID)
		if err != nil {
			return err
		}
		lastUserIndex = idx

		r := req.(*schedulerRequest)

		s.queueDuration.Observe(time.Since(r.enqueueTime).Seconds())
		r.queueSpan.Finish()

		/*
		  We want to dequeue the next unexpired request from the chosen tenant queue.
		  The chance of choosing a particular tenant for dequeueing is (1/active_tenants).
		  This is problematic under load, especially with other middleware enabled such as
		  querier.split-by-interval, where one request may fan out into many.
		  If expired requests aren't exhausted before checking another tenant, it would take
		  n_active_tenants * n_expired_requests_at_front_of_queue requests being processed
		  before an active request was handled for the tenant in question.
		  If this tenant meanwhile continued to queue requests,
		  it's possible that it's own queue would perpetually contain only expired requests.
		*/

		if r.ctx.Err() != nil {
			// Remove from pending requests.
			s.cancelRequestAndRemoveFromPending(r.frontendAddress, r.queryID)

			lastUserIndex = lastUserIndex.ReuseLastUser()
			continue
		}

		if err := s.forwardRequestToQuerier(querier, r); err != nil {
			return err
		}
	}

	return errSchedulerIsNotRunning
}

func (s *Scheduler) NotifyQuerierShutdown(_ context.Context, req *schedulerpb.NotifyQuerierShutdownRequest) (*schedulerpb.NotifyQuerierShutdownResponse, error) {
	level.Info(s.log).Log("msg", "received shutdown notification from querier", "querier", req.GetQuerierID())
	s.requestQueue.NotifyQuerierShutdown(req.GetQuerierID())

	return &schedulerpb.NotifyQuerierShutdownResponse{}, nil
}

func (s *Scheduler) forwardRequestToQuerier(querier schedulerpb.SchedulerForQuerier_QuerierLoopServer, req *schedulerRequest) error {
	// Make sure to cancel request at the end to cleanup resources.
	defer s.cancelRequestAndRemoveFromPending(req.frontendAddress, req.queryID)

	// Handle the stream sending & receiving on a goroutine so we can
	// monitoring the contexts in a select and cancel things appropriately.
	errCh := make(chan error, 1)
	go func() {
		err := querier.Send(&schedulerpb.SchedulerToQuerier{
			UserID:          req.userID,
			QueryID:         req.queryID,
			FrontendAddress: req.frontendAddress,
			HttpRequest:     req.request,
			StatsEnabled:    req.statsEnabled,
		})
		if err != nil {
			errCh <- err
			return
		}

		_, err = querier.Recv()
		errCh <- err
	}()

	select {
	case <-req.ctx.Done():
		// If the upstream request is cancelled (eg. frontend issued CANCEL or closed connection),
		// we need to cancel the downstream req. Only way we can do that is to close the stream (by returning error here).
		// Querier is expecting this semantics.
		return req.ctx.Err()

	case err := <-errCh:
		// Is there was an error handling this request due to network IO,
		// then error out this upstream request _and_ stream.

		if err != nil {
			s.forwardErrorToFrontend(req.ctx, req, err)
		}
		return err
	}
}

// orgIDHeader returns the first X-Scope-OrgID value found in an HTTPRequest's
// headers (case-insensitive), or "" if the header is absent.
func orgIDHeader(req *httpgrpc.HTTPRequest) string {
	if req == nil {
		return ""
	}
	for _, h := range req.Headers {
		if h == nil {
			continue
		}
		if strings.EqualFold(h.Key, user.OrgIDHeaderName) && len(h.Values) > 0 {
			return h.Values[0]
		}
	}
	return ""
}

func (s *Scheduler) forwardErrorToFrontend(ctx context.Context, req *schedulerRequest, requestErr error) {
	// Defence in depth: refuse to open an outbound gRPC connection to an
	// address we would never have accepted at INIT time. This closes the
	// window where a buggy caller (or test harness) stored an unsafe
	// address past validation.
	if err := validateFrontendAddress(req.frontendAddress); err != nil {
		level.Warn(s.log).Log("msg", "refusing to forward error to invalid frontend address", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}
	opts, err := s.cfg.GRPCClientConfig.DialOption([]grpc.UnaryClientInterceptor{
		otgrpc.OpenTracingClientInterceptor(opentracing.GlobalTracer()),
		middleware.ClientUserHeaderInterceptor},
		nil)
	if err != nil {
		level.Warn(s.log).Log("msg", "failed to create gRPC options for the connection to frontend to report error", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}

	conn, err := grpc.DialContext(ctx, req.frontendAddress, opts...)
	if err != nil {
		level.Warn(s.log).Log("msg", "failed to create gRPC connection to frontend to report error", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}

	defer func() {
		_ = conn.Close()
	}()

	client := frontendv2pb.NewFrontendForQuerierClient(conn)

	userCtx := user.InjectOrgID(ctx, req.userID)
	_, err = client.QueryResult(userCtx, &frontendv2pb.QueryResultRequest{
		QueryID: req.queryID,
		HttpResponse: &httpgrpc.HTTPResponse{
			Code: http.StatusInternalServerError,
			Body: []byte(requestErr.Error()),
		},
	})

	if err != nil {
		level.Warn(s.log).Log("msg", "failed to forward error to frontend", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}
}

func (s *Scheduler) isRunningOrStopping() bool {
	st := s.State()
	return st == services.Running || st == services.Stopping
}

func (s *Scheduler) starting(ctx context.Context) error {
	s.subservicesWatcher.WatchManager(s.subservices)

	if err := services.StartManagerAndAwaitHealthy(ctx, s.subservices); err != nil {
		return errors.Wrap(err, "unable to start scheduler subservices")
	}

	return nil
}

func (s *Scheduler) running(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-s.subservicesWatcher.Chan():
			return errors.Wrap(err, "scheduler subservice failed")
		}
	}
}

// Close the Scheduler.
func (s *Scheduler) stopping(_ error) error {
	// This will also stop the requests queue, which stop accepting new requests and errors out any pending requests.
	return services.StopManagerAndAwaitStopped(context.Background(), s.subservices)
}

func (s *Scheduler) cleanupMetricsForInactiveUser(user string) {
	s.queueLength.DeleteLabelValues(user)
	s.discardedRequests.DeleteLabelValues(user)
}

func (s *Scheduler) getConnectedFrontendClientsMetric() float64 {
	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	count := 0
	for _, workers := range s.connectedFrontends {
		count += workers.connections
	}

	return float64(count)
}
