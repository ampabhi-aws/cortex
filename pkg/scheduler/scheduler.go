package scheduler

import (
	"context"
	"flag"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
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

	// Monotonic counter used to tag every accepted FrontendLoop stream with a
	// unique, server-side identifier. We scope pendingRequests to this
	// identifier so a peer can only cancel entries it enqueued on the same
	// stream — regardless of what FrontendAddress it declares in INIT.
	frontendConnCounter uint64

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
	unmatchedCancellations   prometheus.Counter
}

// requestKey scopes a pending request to the FrontendLoop gRPC stream that
// enqueued it (connID is a server-assigned, monotonically increasing id
// from Scheduler.frontendConnCounter), not to the self-declared
// FrontendAddress on the wire. This makes it impossible for one peer to
// cancel another peer's pending requests even if it impersonates the
// victim's FrontendAddress on an unauthenticated gRPC listener.
type requestKey struct {
	connID       uint64
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
	s.unmatchedCancellations = promauto.With(registerer).NewCounter(prometheus.CounterOpts{
		Name: "cortex_query_scheduler_cancel_unmatched_total",
		Help: "Total number of CANCEL messages from a frontend connection that did not match any pending request on that connection. A sustained non-zero rate is a strong signal of a spoofed-cancel sweep against the scheduler.",
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
	// connID identifies the FrontendLoop gRPC stream that enqueued this
	// request; it is the primary ownership key in pendingRequests.
	connID          uint64
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
	connID, frontendAddress, frontendCtx, err := s.frontendConnected(frontend)
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
			err = s.enqueueRequest(frontendCtx, connID, frontendAddress, msg)
			switch {
			case err == nil:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}
			case err == queue.ErrTooManyRequests:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.TOO_MANY_REQUESTS_PER_TENANT}
			default:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
			}

		case schedulerpb.CANCEL:
			// Cancellation is scoped to this gRPC stream (connID). A peer
			// that spoofs another frontend's FrontendAddress will not have
			// matching pendingRequests entries for its own connID, so the
			// delete is a no-op and we record it as an unmatched cancel.
			if !s.cancelRequestAndRemoveFromPending(connID, frontendAddress, msg.QueryID) {
				s.unmatchedCancellations.Inc()
			}
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

func (s *Scheduler) frontendConnected(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) (uint64, string, context.Context, error) {
	msg, err := frontend.Recv()
	if err != nil {
		return 0, "", nil, err
	}
	if msg.Type != schedulerpb.INIT || msg.FrontendAddress == "" {
		return 0, "", nil, errors.New("no frontend address")
	}

	// Assign a unique, server-side connection id to this FrontendLoop stream.
	// pendingRequests entries are keyed by this id in addition to
	// FrontendAddress + QueryID, so a peer cannot touch another peer's
	// entries by spoofing FrontendAddress on INIT.
	connID := atomic.AddUint64(&s.frontendConnCounter, 1)

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
	return connID, msg.FrontendAddress, cf.ctx, nil
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

func (s *Scheduler) enqueueRequest(frontendContext context.Context, connID uint64, frontendAddr string, msg *schedulerpb.FrontendToScheduler) error {
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

	req := &schedulerRequest{
		connID:          connID,
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
		s.pendingRequests[requestKey{connID: connID, frontendAddr: frontendAddr, queryID: msg.QueryID}] = req
	})
}

// cancelRequestAndRemoveFromPending cancels the pending request owned by this
// FrontendLoop stream (connID). It returns true when a matching entry was
// found and canceled, false otherwise. The caller uses the boolean to
// distinguish legitimate cancellations from spoofed/duplicate sweeps.
//
// This method doesn't do removal from the queue.
func (s *Scheduler) cancelRequestAndRemoveFromPending(connID uint64, frontendAddr string, queryID uint64) bool {
	s.pendingRequestsMu.Lock()
	defer s.pendingRequestsMu.Unlock()

	key := requestKey{connID: connID, frontendAddr: frontendAddr, queryID: queryID}
	req, ok := s.pendingRequests[key]
	if ok && req != nil {
		req.ctxCancel()
	}
	delete(s.pendingRequests, key)
	return ok
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
			s.cancelRequestAndRemoveFromPending(r.connID, r.frontendAddress, r.queryID)

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
	defer s.cancelRequestAndRemoveFromPending(req.connID, req.frontendAddress, req.queryID)

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

func (s *Scheduler) forwardErrorToFrontend(ctx context.Context, req *schedulerRequest, requestErr error) {
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
