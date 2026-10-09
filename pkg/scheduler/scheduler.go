package scheduler

import (
	"context"
	"flag"
	"io"
	"net/http"
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
	"go.uber.org/atomic"
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

	requestQueue *queue.RequestQueue
	activeUsers  *util.ActiveUsersCleanupService

	pendingRequestsMu sync.Mutex
	pendingRequests   map[requestKey]*schedulerRequest // Request is kept in this map even after being dispatched to querier. It can still be canceled at that time.

	// nextFrontendConnID is used to give each FrontendLoop stream a server-assigned,
	// non-forgeable connection ID. The ID is used as part of the pending-request key so a
	// CANCEL (or a late dispatch) coming from one frontend stream cannot affect pending
	// requests created by another stream, even if two streams assert the same
	// FrontendAddress and QueryID (defense in depth; see finding
	// 01a11d640c4575099c897742cbef0b17).
	nextFrontendConnID atomic.Uint64

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

// requestKey identifies a pending request in the scheduler. frontendConnID is a
// server-assigned per-FrontendLoop-stream connection ID; combined with the
// client-asserted frontendAddr/queryID it ensures that each stream can only touch its
// own pending entries, so a hostile stream claiming the same FrontendAddress or
// guessing a QueryID cannot cancel or overwrite another stream's in-flight request.
type requestKey struct {
	frontendConnID uint64
	frontendAddr   string
	queryID        uint64
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
	// frontendConnID identifies the FrontendLoop stream that enqueued this request.
	// It is server-assigned (not caller-supplied) and used to bind the pendingRequests
	// entry to the stream so cross-stream cancellation is impossible.
	frontendConnID uint64
	userID         string
	queryID        uint64
	request        *httpgrpc.HTTPRequest
	statsEnabled   bool

	enqueueTime time.Time

	ctx       context.Context
	ctxCancel context.CancelFunc
	queueSpan opentracing.Span

	// This is only used for testing.
	parentSpanContext opentracing.SpanContext
}

// FrontendLoop handles connection from frontend.
func (s *Scheduler) FrontendLoop(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) error {
	frontendConnID, frontendAddress, frontendCtx, err := s.frontendConnected(frontend)
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
			err = s.enqueueRequest(frontendCtx, frontendConnID, frontendAddress, msg)
			switch {
			case err == nil:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}
			case err == queue.ErrTooManyRequests:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.TOO_MANY_REQUESTS_PER_TENANT}
			default:
				resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
			}

		case schedulerpb.CANCEL:
			// Only cancel pending requests that this very stream created. A stream
			// that forged another frontend's FrontendAddress still cannot touch
			// that frontend's pending entries because the connID won't match.
			s.cancelRequestAndRemoveFromPending(requestKey{frontendConnID: frontendConnID, frontendAddr: frontendAddress, queryID: msg.QueryID})
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

	// Assign a server-side connection ID that the caller cannot forge. It is used as
	// part of the pendingRequests key below, binding each pending request to the
	// FrontendLoop stream that enqueued it.
	connID := s.nextFrontendConnID.Inc()

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

func (s *Scheduler) enqueueRequest(frontendContext context.Context, frontendConnID uint64, frontendAddr string, msg *schedulerpb.FrontendToScheduler) error {
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
		frontendAddress: frontendAddr,
		frontendConnID:  frontendConnID,
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
		s.pendingRequests[requestKey{frontendConnID: frontendConnID, frontendAddr: frontendAddr, queryID: msg.QueryID}] = req
	})
}

// cancelRequestAndRemoveFromPending cancels the pending request identified by key, if
// present. It does not remove the request from the user queue. The caller must supply
// the full requestKey including the server-assigned frontendConnID, so that only the
// stream that created a pending entry can cancel or remove it.
func (s *Scheduler) cancelRequestAndRemoveFromPending(key requestKey) {
	s.pendingRequestsMu.Lock()
	defer s.pendingRequestsMu.Unlock()

	req := s.pendingRequests[key]
	if req != nil {
		req.ctxCancel()
	}
	delete(s.pendingRequests, key)
}

// pendingKey returns the full pending-requests key for r.
func pendingKey(r *schedulerRequest) requestKey {
	return requestKey{frontendConnID: r.frontendConnID, frontendAddr: r.frontendAddress, queryID: r.queryID}
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
			s.cancelRequestAndRemoveFromPending(pendingKey(r))

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
	defer s.cancelRequestAndRemoveFromPending(pendingKey(req))

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
